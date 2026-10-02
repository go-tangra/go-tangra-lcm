//go:build integration

// An imported ACME certificate (issued elsewhere, e.g. by certbot) is renewed
// by lcm through the issuer's own ACME account against a real Pebble, keeping
// the imported key, and the renewal supersedes the imported row.
//
// Run: go test -tags integration -run ImportedCertificate ./tests/integration/
// (needs Docker; skips cleanly without it).
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

func TestImportedCertificateRenewsThroughACME(t *testing.T) {
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })
	pebble := start(t, ctx, nw.Name, testcontainers.ContainerRequest{
		Image: pebbleImage, ExposedPorts: []string{"14000/tcp"},
		Cmd: []string{"-config", "test/config/pebble-config.json"},
		// The DNS-01 side is not under test here (the issuer uses the no-op
		// "manual" provider): Pebble accepts every challenge.
		Env:        map[string]string{"PEBBLE_VA_ALWAYS_VALID": "1", "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0"},
		WaitingFor: wait.ForListeningPort("14000/tcp").WithStartupTimeout(60 * time.Second),
	})

	st := memstore.New()
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	az := authz.New(st)
	aw := audit.NewWriter(st, nil)
	t.Cleanup(aw.Close)
	svc := issue.New(st, ca.New(st, env), env, az, aw, time.Now)
	admin := authz.Subjects{TenantID: "t1", UserID: "u-admin", Roles: []string{"admin"}}

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	accDER, _ := x509.MarshalPKCS8PrivateKey(accountKey)
	iv, err := svc.CreateIssuer(ctx, admin, issue.IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "*", Enabled: true,
		// Loopback directory: lcm accepts Pebble's test TLS certificate.
		ACMEDirectoryURL: "https://" + pebble.url("14000/tcp") + "/dir", ACMEEmail: "ops@example.org", DNSProvider: "manual",
		Settings: sealed.Settings{"acme_account_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: accDER}))},
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	// The "certbot" certificate: issued by some other CA for two names, with a
	// PKCS#1 RSA key (certbot's historic RSA format).
	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "app.example.test"},
		DNSNames: []string{"app.example.test", "www.example.test"}, NotBefore: time.Now().Add(-80 * 24 * time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svc.ImportACME(ctx, admin, issue.ImportInput{
		IssuerID: iv.ID, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})),
		AutoRenew: true,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	// What the scheduler (and the import handler, for a due certificate) does.
	rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	renewed, err := svc.RenewSystem(rctx, admin.TenantID, imported.ID)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	blk, _ := pem.Decode([]byte(renewed.CertPEM))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(leaf.DNSNames, ",") != "app.example.test,www.example.test" {
		t.Fatalf("renewed names = %v", leaf.DNSNames)
	}
	if !certKey.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("renewal did not keep the imported key")
	}
	if !strings.Contains(leaf.Issuer.CommonName, "Pebble") {
		t.Fatalf("renewed by %q, want the issuer's ACME CA", leaf.Issuer.CommonName)
	}
	if renewed.Certificate.Kind != "generic" || renewed.Certificate.IssuerID != iv.ID || !renewed.Certificate.AutoRenew || !renewed.Certificate.HasKey {
		t.Fatalf("renewed view = %+v", renewed.Certificate)
	}
	old, err := st.GetCertificate(ctx, admin.TenantID, imported.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.SupersededBy == nil || *old.SupersededBy != renewed.Certificate.ID {
		t.Fatalf("imported row not superseded: %v", old.SupersededBy)
	}
	// The key stays downloadable (and identical) on the renewed certificate.
	keyPEM, err := svc.DownloadKey(ctx, admin, renewed.Certificate.ID)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil || !certKey.PublicKey.Equal(k.(*rsa.PrivateKey).Public()) {
		t.Fatalf("renewed key: %v", err)
	}
}
