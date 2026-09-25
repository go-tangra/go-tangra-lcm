package lcmidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// keylessLCM mimics lcm's keyless enroll listener: server-auth-only TLS 1.3
// presenting an SVID (URI SAN spiffe://example.org/svc/lcm, no DNS name)
// signed by the mesh root, answering POST /api/lcm/v1/enroll.
type keylessLCM struct {
	ca   *fakeCA
	srv  *httptest.Server
	hits atomic.Int32
}

func newKeylessLCM(t *testing.T) *keylessLCM {
	t.Helper()
	k := &keylessLCM{ca: newFakeCA(t)}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/svc/lcm"}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, k.ca.cert, &key.PublicKey, k.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	k.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.hits.Add(1)
		var in struct {
			CSRPEM string `json:"csr_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad", http.StatusUnprocessableEntity)
			return
		}
		b := k.ca.sign(t, in.CSRPEM, time.Hour)
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": b.GetCertPem(), "bundle_pem": b.GetBundlePem()})
	}))
	k.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	k.srv.StartTLS()
	t.Cleanup(k.srv.Close)
	return k
}

func (k *keylessLCM) cfg() NetConfig {
	return NetConfig{EnrollURL: k.srv.URL + "/api/lcm/v1/enroll", LCMGRPCTarget: "lcm:9945", TrustDomain: "example.org",
		ServiceName: "gateway", EnrollmentToken: "join-token"}
}

// meshTLS is what the framework's tlsconf.EnrollClientConfig builds: chain to
// the mesh roots and require the lcm SPIFFE ID, no host name check.
func meshTLS(root *x509.Certificate, want string) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // #nosec G402 -- test stand-in for tlsconf.EnrollClientConfig; verified below
		VerifyConnection: func(cs tls.ConnectionState) error {
			leaf := cs.PeerCertificates[0]
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want {
				return errors.New("spiffe id mismatch")
			}
			return nil
		},
	}
}

func TestNetEnrollVerifiedAgainstMeshBundle(t *testing.T) {
	k := newKeylessLCM(t)
	cfg := k.cfg()
	cfg.EnrollTLS = meshTLS(k.ca.cert, "spiffe://example.org/svc/lcm")
	p, err := NewNet(context.Background(), cfg)
	if err != nil {
		t.Fatalf("verified enroll: %v", err)
	}
	defer func() { _ = p.Close() }()
	id, _, err := p.Current(context.Background())
	if err != nil || id.ID().String() != "spiffe://example.org/svc/gateway" {
		t.Fatalf("identity = %v, %v", id, err)
	}
	if k.hits.Load() != 1 {
		t.Fatalf("enroll calls = %d", k.hits.Load())
	}
}

// A server that fails verification never receives the join token.
func TestNetEnrollRefusesUnverifiedServer(t *testing.T) {
	other := newFakeCA(t)
	cases := map[string]func(k *keylessLCM) *tls.Config{
		"wrong mesh root": func(*keylessLCM) *tls.Config { return meshTLS(other.cert, "spiffe://example.org/svc/lcm") },
		"wrong spiffe id": func(k *keylessLCM) *tls.Config { return meshTLS(k.ca.cert, "spiffe://example.org/svc/auth") },
		// Public verification (system roots + host name) can never accept an SVID.
		"public (no enroll tls)": func(*keylessLCM) *tls.Config { return nil },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			k := newKeylessLCM(t)
			cfg := k.cfg()
			cfg.EnrollTLS = mk(k)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if p, err := NewNet(ctx, cfg); err == nil {
				_ = p.Close()
				t.Fatal("enrolled against an unverified server")
			}
			if k.hits.Load() != 0 {
				t.Fatalf("join token reached an unverified server (%d calls)", k.hits.Load())
			}
		})
	}
}

func TestNetEnrollTLSExcludesInsecure(t *testing.T) {
	k := newKeylessLCM(t)
	cfg := k.cfg()
	cfg.Insecure = true
	cfg.EnrollTLS = meshTLS(k.ca.cert, "spiffe://example.org/svc/lcm")
	_, err := NewNet(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

// A persisted SVID is reused only while it names this workload: after a trust
// domain (or service) change the provider must enroll afresh.
func TestNetLoadPersistedRejectsOtherIdentity(t *testing.T) {
	ca := newFakeCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://example.org/svc/inventory")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{uri}}, key)
	if err != nil {
		t.Fatal(err)
	}
	b := ca.sign(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), time.Hour)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	rec, _ := json.Marshal(persistedSVID{CertPEM: b.CertPem, BundlePEM: b.BundlePem,
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))})
	file := filepath.Join(t.TempDir(), "svid.json")
	if err := os.WriteFile(file, rec, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		td, svc string
		reuse   bool
	}{
		{"example.org", "inventory", true},
		{"infra.example.com", "inventory", false},
		{"example.org", "asset", false},
	} {
		p := &NetProvider{cfg: NetConfig{TrustDomain: tc.td, ServiceName: tc.svc, StateFile: file}, now: time.Now}
		if got := p.loadPersisted() != nil; got != tc.reuse {
			t.Errorf("%s/%s: reused=%v, want %v", tc.td, tc.svc, got, tc.reuse)
		}
	}
}
