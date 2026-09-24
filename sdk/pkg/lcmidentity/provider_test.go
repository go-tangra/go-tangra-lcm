package lcmidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmv1 "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1"
)

// fakeCA signs enrollment CSRs for the test.
type fakeCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org LCM Root"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeCA{cert: cert, key: key}
}

func (c *fakeCA) rootPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}))
}

func (c *fakeCA) sign(t *testing.T, csrPEM string, ttl time.Duration) *lcmv1.CertificateBundle {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		t.Fatal("bad CSR PEM")
	}
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: req.Subject, URIs: req.URIs,
		NotBefore: now, NotAfter: now.Add(ttl), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, req.PublicKey, c.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sid := ""
	if len(req.URIs) > 0 {
		sid = req.URIs[0].String()
	}
	return &lcmv1.CertificateBundle{
		CertPem:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		BundlePem:   c.rootPEM(),
		Certificate: &lcmv1.Certificate{Serial: leaf.SerialNumber.String(), SpiffeId: sid, NotAfter: timestamppb.New(leaf.NotAfter)},
	}
}

type fakeEnroll struct {
	lcmv1.UnimplementedEnrollmentServer
	ca   *fakeCA
	t    *testing.T
	ttl  time.Duration
	seen atomic.Int32
}

func (s *fakeEnroll) Enroll(_ context.Context, req *lcmv1.EnrollRequest) (*lcmv1.CertificateBundle, error) {
	s.seen.Add(1)
	return s.ca.sign(s.t, req.GetCsrPem(), s.ttl), nil
}

type fakeAgent struct {
	lcmv1.UnimplementedAgentServer
	update *lcmv1.CertificateUpdate
}

func (s *fakeAgent) Watch(_ *lcmv1.WatchRequest, srv lcmv1.Agent_WatchServer) error {
	if s.update != nil {
		_ = srv.Send(s.update)
	}
	<-srv.Context().Done()
	return nil
}

func dialFake(t *testing.T, en *fakeEnroll, ag *fakeAgent) grpc.ClientConnInterface {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	lcmv1.RegisterEnrollmentServer(srv, en)
	lcmv1.RegisterAgentServer(srv, ag)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// credSource mirrors the framework's structural cred.Source, proving transport
// can obtain key material from this external provider.
type credSource interface {
	Credential() (*tls.Certificate, error)
}

func TestProviderEnrollsAndCredentialChains(t *testing.T) {
	ca := newFakeCA(t)
	en := &fakeEnroll{ca: ca, t: t, ttl: time.Hour}
	conn := dialFake(t, en, &fakeAgent{})
	p, err := New(context.Background(), Config{Conn: conn, TenantID: "11111111-1111-7111-8111-111111111111", TrustDomain: "example.org", ServiceName: "notification"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	id, bundle, err := p.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if id.ID().String() != "spiffe://example.org/svc/notification" {
		t.Fatalf("id = %s", id.ID())
	}
	if id.ID().TrustDomain() != "example.org" || id.ID().ServiceName() != "notification" {
		t.Fatalf("id parts wrong: %s", id.ID())
	}
	if len(bundle.Roots()) != 1 {
		t.Fatalf("bundle roots = %d", len(bundle.Roots()))
	}

	// The provider satisfies the structural credential source, and its leaf
	// chains to the trust root with the private key it holds.
	var cs credSource = p
	crt, err := cs.Credential()
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(bundle.Roots()[0])
	leaf, _ := x509.ParseCertificate(crt.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the trust root: %v", err)
	}
	if crt.PrivateKey == nil {
		t.Fatal("no private key in credential")
	}
}

func TestProviderRenewsOnAgentUpdate(t *testing.T) {
	ca := newFakeCA(t)
	en := &fakeEnroll{ca: ca, t: t, ttl: time.Hour}
	// The agent streams one update for our SPIFFE id, which pokes a renewal.
	ag := &fakeAgent{update: &lcmv1.CertificateUpdate{Id: "1-0", Type: "renewed", SpiffeId: "spiffe://example.org/svc/notification"}}
	conn := dialFake(t, en, ag)
	p, err := New(context.Background(), Config{Conn: conn, TenantID: "11111111-1111-7111-8111-111111111111", TrustDomain: "example.org", ServiceName: "notification", RenewBefore: time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := p.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	select {
	case u := <-ch:
		if u.Err != nil {
			t.Fatalf("update error: %v", u.Err)
		}
		if u.Bundle == nil || u.Bundle.Version() < 2 {
			t.Fatalf("expected a renewed bundle (version >=2), got %+v", u.Bundle)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no renewal update after the agent stream event")
	}
	if en.seen.Load() < 2 {
		t.Fatalf("expected at least 2 enrollments (initial + renewal), got %d", en.seen.Load())
	}
}
