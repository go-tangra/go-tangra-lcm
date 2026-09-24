//go:build integration

// T103 (SC-005): the lcm "Freya DNS" ACME DNS-01 provider issues a certificate
// from a REAL Pebble whose validation authority checks the DNS-01 TXT record
// for real (no PEBBLE_VA_ALWAYS_VALID): Pebble resolves through a real
// PowerDNS Recursor, which forwards the hosted zone to a real PowerDNS
// Authoritative server, where the dns module wrote the challenge value.
//
// The dns side is the real dns module code (zones + records + acmechallenge +
// the dns.v1 grpcapi handlers over the PowerDNS HTTP clients) built from
// services/dns/tests/integration/challengesrv: lcm may not import services/dns
// (dns depends on lcm), so the helper runs as a separate process. The SPIFFE
// mTLS hop is replaced by the helper's interceptor asserting the lcm identity;
// the dns handler's own allowed-caller check still runs. lcm reaches it with
// its production client (pkg/dnschallenge) behind acme.NewProviderWith.
//
// Run: go test -tags integration -run FreyaDNS ./tests/integration/
// (needs Docker; skips cleanly without it).
package integration

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/dnschallenge"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
)

const (
	pdnsAuthImage     = "powerdns/pdns-auth-49@sha256:b554df74bbde1afa7caedad4af9c91378be6d46d05807d089b3c7c443002e684"
	pdnsRecursorImage = "powerdns/pdns-recursor-53@sha256:175d551ce52fa5c6bf0a0c19d6872791a4c928f6fb00a696534c1174693da3f7"
	pebbleImage       = "ghcr.io/letsencrypt/pebble:latest"
	dnsTenant         = "11111111-1111-7111-8111-111111111111"
	authKey           = "it-auth-key"
	recursorKey       = "it-recursor-key"
)

// recursorYAML enables the recursor API (with the api_dir the forward-zone
// API needs), answers any client and skips DNSSEC validation (".test" is not
// delegated from the root).
const recursorYAML = `webservice:
  webserver: true
  address: 0.0.0.0
  port: 8082
  api_key: "` + recursorKey + `"
  api_dir: /tmp
  allow_from: ["0.0.0.0/0"]
incoming:
  allow_from: ["0.0.0.0/0"]
dnssec:
  validation: "off"
`

type started struct {
	c   testcontainers.Container
	ip  string
	url func(port string) string
}

func start(t *testing.T, ctx context.Context, nw string, req testcontainers.ContainerRequest) started {
	t.Helper()
	req.Networks = []string{nw}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("start %s: %v", req.Image, err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if rc, err := c.Logs(context.Background()); err == nil {
				b := make([]byte, 8192)
				n, _ := rc.Read(b)
				t.Logf("%s logs:\n%s", req.Image, b[:n])
			}
		}
		_ = c.Terminate(context.Background())
	})
	ip, err := c.ContainerIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return started{c: c, ip: ip, url: func(port string) string {
		p, err := c.MappedPort(ctx, port)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("127.0.0.1:%s", p.Port())
	}}
}

// helper builds and starts the dns-side challenge server; it returns its gRPC address.
func helper(t *testing.T, args ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "challengesrv")
	build := exec.Command("go", "build", "-tags", "integration", "-o", bin, "./tests/integration/challengesrv")
	build.Dir = filepath.Join("..", "..", "..", "dns")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build dns challenge helper: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, args...) // #nosec G204 -- test helper built above
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if addr, ok := strings.CutPrefix(sc.Text(), "READY "); ok {
				ready <- addr
			}
		}
	}()
	select {
	case addr := <-ready:
		return addr
	case <-time.After(60 * time.Second):
		t.Fatal("dns challenge helper did not become ready")
	}
	return ""
}

// authTXT asks the authoritative server directly (over TCP) for the TXT
// values at name.
func authTXT(ctx context.Context, authTCP, name string) ([]string, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", authTCP)
	}}
	txt, err := r.LookupTXT(ctx, name)
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return nil, nil
	}
	return txt, err
}

// observed wraps the production dnschallenge client as the provider's
// FreyaDNSClient and records what the authoritative server served right
// after each Present.
type observed struct {
	c       *dnschallenge.Client
	authTCP string
	mu      sync.Mutex
	seen    map[string][]string
	zones   []string
}

func (o *observed) Present(ctx context.Context, tenantID, domain, fqdn, value string) error {
	zone, err := o.c.Present(ctx, tenantID, domain, fqdn, value)
	if err != nil {
		return err
	}
	txt, _ := authTXT(ctx, o.authTCP, fqdn)
	o.mu.Lock()
	o.seen[value] = txt
	o.zones = append(o.zones, zone)
	o.mu.Unlock()
	return nil
}

func (o *observed) CleanUp(ctx context.Context, tenantID, domain, fqdn, value string) error {
	_, err := o.c.CleanUp(ctx, tenantID, domain, fqdn, value)
	return err
}

func TestFreyaDNS_IssuesWithRealDNS01Validation(t *testing.T) {
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })

	auth := start(t, ctx, nw.Name, testcontainers.ContainerRequest{
		Image: pdnsAuthImage, ExposedPorts: []string{"8081/tcp", "53/tcp"},
		Env:        map[string]string{"PDNS_AUTH_API_KEY": authKey},
		WaitingFor: wait.ForHTTP("/api/v1/servers").WithPort("8081/tcp").WithHeaders(map[string]string{"X-API-Key": authKey}).WithStartupTimeout(60 * time.Second),
	})
	rec := start(t, ctx, nw.Name, testcontainers.ContainerRequest{
		Image: pdnsRecursorImage, ExposedPorts: []string{"8082/tcp"},
		Files:      []testcontainers.ContainerFile{{Reader: strings.NewReader(recursorYAML), ContainerFilePath: "/etc/powerdns/recursor.d/10-it.yml", FileMode: 0o644}},
		WaitingFor: wait.ForHTTP("/api/v1/servers").WithPort("8082/tcp").WithHeaders(map[string]string{"X-API-Key": recursorKey}).WithStartupTimeout(60 * time.Second),
	})
	pebble := start(t, ctx, nw.Name, testcontainers.ContainerRequest{
		Image: pebbleImage, ExposedPorts: []string{"14000/tcp"},
		Cmd: []string{"-config", "test/config/pebble-config.json", "-dnsserver", rec.ip + ":53"},
		// Real validation: no PEBBLE_VA_ALWAYS_VALID.
		Env:        map[string]string{"PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0"},
		WaitingFor: wait.ForListeningPort("14000/tcp").WithStartupTimeout(60 * time.Second),
	})

	grpcAddr := helper(t, "-pdns-url", "http://"+auth.url("8081/tcp"), "-pdns-key", authKey,
		"-recursor-url", "http://"+rec.url("8082/tcp"), "-recursor-key", recursorKey, "-forward-host", auth.ip,
		"-tenant", dnsTenant, "-zone", "example.test")
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	authTCP := auth.url("53/tcp")
	obs := &observed{c: dnschallenge.New(conn), authTCP: authTCP, seen: map[string][]string{}}

	provider, err := acme.NewProviderWith(acme.FreyaDNS, nil, acme.ProviderDeps{FreyaDNS: obs, TenantID: dnsTenant})
	if err != nil {
		t.Fatal(err)
	}
	accountKey, err := acme.GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	client, err := acme.New(acme.Config{DirectoryURL: "https://" + pebble.url("14000/tcp") + "/dir", AccountKey: accountKey,
		DNS: provider, AllowInsecure: true, PollInterval: 500 * time.Millisecond, Timeout: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Register(ctx); err != nil {
		t.Fatalf("register: %v", err)
	}

	const name = "app.example.test"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := client.Obtain(ctx, csr, []string{name})
	if err != nil {
		t.Fatalf("obtain: %v", err)
	}
	block, _ := pem.Decode([]byte(chain))
	if block == nil {
		t.Fatal("no certificate in chain")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != name {
		t.Fatalf("certificate names = %v", cert.DNSNames)
	}

	// The value was really served by the authoritative server during validation...
	obs.mu.Lock()
	if len(obs.seen) != 1 || len(obs.zones) != 1 || obs.zones[0] != "example.test." {
		t.Fatalf("presented = %v zones %v", obs.seen, obs.zones)
	}
	for value, txt := range obs.seen {
		if len(txt) != 1 || txt[0] != value {
			t.Fatalf("authoritative TXT during validation = %v, want [%s]", txt, value)
		}
	}
	obs.mu.Unlock()
	// ...and no _acme-challenge TXT remains afterwards (SC-005).
	left, err := authTXT(ctx, authTCP, "_acme-challenge."+name)
	if err != nil {
		t.Fatalf("query after issuance: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("_acme-challenge TXT left behind: %v", left)
	}

	// A name outside the tenant's zones is refused and nothing is written.
	csr2, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"app.unhosted.test"}}, key)
	if _, err := client.Obtain(ctx, csr2, []string{"app.unhosted.test"}); !errors.Is(err, acme.ErrProvider) {
		t.Fatalf("unhosted name = %v, want provider refusal", err)
	}

	// Negative control proving the VA validates for real: a provider that
	// publishes nothing ("manual") gets the authorization refused.
	manual, _ := acme.NewProvider("manual", nil)
	noop, err := acme.New(acme.Config{DirectoryURL: "https://" + pebble.url("14000/tcp") + "/dir", AccountKey: accountKey,
		DNS: manual, AllowInsecure: true, PollInterval: 500 * time.Millisecond, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	csr3, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"other.example.test"}}, key)
	if _, err := noop.Obtain(ctx, csr3, []string{"other.example.test"}); !errors.Is(err, acme.ErrChallenge) {
		t.Fatalf("unpublished challenge = %v, want the VA to refuse it", err)
	}
}
