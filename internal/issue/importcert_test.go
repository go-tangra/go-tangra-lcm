package issue

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

// importCA is a throwaway "ACME CA" (root) that signs leaves for the tests.
type importCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newImportCA(t *testing.T) importCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test ACME Root"},
		NotBefore: clk.Add(-time.Hour), NotAfter: clk.Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return importCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

var importSerial = int64(1000)

// leaf signs a leaf for pub valid [nb, na) with the given names.
func (ca importCA) leaf(t *testing.T, pub crypto.PublicKey, nb, na time.Time, mut func(*x509.Certificate)) string {
	t.Helper()
	importSerial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(importSerial), Subject: pkix.Name{CommonName: "www.example.com"},
		DNSNames: []string{"www.example.com", "example.com"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mut != nil {
		mut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pkcs8PEM(t *testing.T, k any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func importFixture(t *testing.T) (*fixture, IssuerView, importCA) {
	t.Helper()
	f := newFixture(t)
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "le", Type: "acme", TrustDomain: "*", Enabled: true,
		ACMEDirectoryURL: "https://127.0.0.1:1/dir", ACMEEmail: "ops@example.org", DNSProvider: "manual",
		Settings: sealed.Settings{"acme_account_key": accountKeyPEM(t)},
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
	return f, iv, newImportCA(t)
}

// TestImportACMECertificate: a certbot-style fullchain + PKCS#1 RSA key is
// stored as a generic certificate of the ACME issuer, renewable, with the key
// sealed as PKCS#8 and downloadable; the import is audited and owned.
func TestImportACMECertificate(t *testing.T) {
	f, iv, ca := importFixture(t)
	ctx := context.Background()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := ca.leaf(t, &rsaKey.PublicKey, clk.Add(-24*time.Hour), clk.Add(89*24*time.Hour), nil)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))

	v, err := f.svc.ImportACME(ctx, f.admin, ImportInput{IssuerID: iv.ID, CertPEM: leaf + ca.pem, ChainPEM: ca.pem, KeyPEM: pkcs1, AutoRenew: true})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if v.Kind != "generic" || v.IssuerID != iv.ID || !v.AutoRenew || !v.HasKey || v.Subject != "www.example.com" ||
		strings.Join(v.SANs, ",") != "www.example.com,example.com" || v.SpiffeID != "" {
		t.Fatalf("view = %+v", v)
	}
	row, err := f.mem.GetCertificate(ctx, f.admin.TenantID, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(row.ChainPEM, "BEGIN CERTIFICATE") != 1 || strings.Count(row.CertPEM, "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("chain dedupe: cert %d chain %d", strings.Count(row.CertPEM, "BEGIN"), strings.Count(row.ChainPEM, "BEGIN"))
	}
	// The key comes back as PKCS#8 (what renewal reuses) and is the same key.
	keyPEM, err := f.svc.DownloadKey(ctx, f.admin, v.ID)
	if err != nil || !strings.HasPrefix(keyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("key = %.40q %v", keyPEM, err)
	}
	sg, err := parseAccountKey(keyPEM)
	if err != nil || !rsaKey.PublicKey.Equal(sg.Public()) {
		t.Fatalf("stored key differs: %v", err)
	}
	// The importer owns it through a grant (not only through the admin role).
	if err := f.az.Check(ctx, authz.Subjects{TenantID: f.admin.TenantID, UserID: f.admin.UserID}, authz.Certificate, v.ID, authz.Use); err != nil {
		t.Fatalf("owner grant: %v", err)
	}
	var imported bool
	for _, r := range f.audits(t) {
		if r.EventType == string(audit.CertificateImported) && r.SubjectID == v.ID && r.Outcome == string(audit.OutcomeOK) {
			imported = true
			if strings.Contains(string(r.Details), "PRIVATE KEY") {
				t.Fatal("key material in the audit row")
			}
		}
	}
	if !imported {
		t.Fatal("certificate_imported not audited")
	}
	// The same certificate again is refused.
	var ve *ValidationError
	if _, err := f.svc.ImportACME(ctx, f.admin, ImportInput{IssuerID: iv.ID, CertPEM: leaf, KeyPEM: pkcs1}); !errors.As(err, &ve) || ve.Field != "certificate" {
		t.Fatalf("duplicate: %v", err)
	}
}

// TestImportACMEKeyFormats: SEC1 EC and PKCS#8 keys import; an expired
// certificate imports too (renewal starts right after, in the handler).
func TestImportACMEKeyFormats(t *testing.T) {
	f, iv, ca := importFixture(t)
	ctx := context.Background()
	ec, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	leaf := ca.leaf(t, &ec.PublicKey, clk.Add(-100*24*time.Hour), clk.Add(-10*24*time.Hour), nil)
	if _, err := f.svc.ImportACME(ctx, f.admin, ImportInput{IssuerID: iv.ID, CertPEM: leaf,
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))}); err != nil {
		t.Fatalf("SEC1 (expired leaf): %v", err)
	}
	ec2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// certbot's privkey.pem may carry the EC parameters block first.
	params := "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n"
	if v, err := f.svc.ImportACME(ctx, f.admin, ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &ec2.PublicKey, clk, clk.Add(time.Hour*24*90), nil),
		KeyPEM: params + pkcs8PEM(t, ec2), AutoRenew: false}); err != nil || v.AutoRenew {
		t.Fatalf("PKCS#8: %+v %v", v, err)
	}
}

// TestImportACMERefusals: every refusal names the field; nothing is stored.
func TestImportACMERefusals(t *testing.T) {
	f, iv, ca := importFixture(t)
	ctx := context.Background()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := ca.leaf(t, &ec.PublicKey, clk, clk.Add(90*24*time.Hour), nil)
	key := pkcs8PEM(t, ec)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ssIssuer, err := f.svc.CreateIssuer(ctx, f.admin, IssuerInput{Name: "ss", Type: "self_signed", TrustDomain: "example.org", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		in    ImportInput
		field string
	}{
		{"self-signed issuer", ImportInput{IssuerID: ssIssuer.ID, CertPEM: good, KeyPEM: key}, "issuer_id"},
		{"unknown issuer", ImportInput{IssuerID: "nope", CertPEM: good, KeyPEM: key}, "issuer_id"},
		{"no certificate", ImportInput{IssuerID: iv.ID, CertPEM: "", KeyPEM: key}, "certificate"},
		{"garbage", ImportInput{IssuerID: iv.ID, CertPEM: "hello", KeyPEM: key}, "certificate"},
		{"trailing text", ImportInput{IssuerID: iv.ID, CertPEM: good + "junk", KeyPEM: key}, "certificate"},
		{"key in cert field", ImportInput{IssuerID: iv.ID, CertPEM: good + key, KeyPEM: key}, "certificate"},
		{"CA as leaf", ImportInput{IssuerID: iv.ID, CertPEM: ca.pem, KeyPEM: key}, "certificate"},
		{"IP SAN", ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &ec.PublicKey, clk, clk.Add(time.Hour), func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.IPv4(10, 0, 0, 1)} }), KeyPEM: key}, "certificate"},
		{"no names", ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &ec.PublicKey, clk, clk.Add(time.Hour), func(c *x509.Certificate) { c.DNSNames = nil; c.Subject.CommonName = "" }), KeyPEM: key}, "certificate"},
		{"bad domain", ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &ec.PublicKey, clk, clk.Add(time.Hour), func(c *x509.Certificate) { c.DNSNames = []string{"bad_name.example.com"} }), KeyPEM: key}, "certificate"},
		{"no key", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: ""}, "key"},
		{"mismatched key", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: pkcs8PEM(t, other)}, "key"},
		{"weak RSA", ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &weak.PublicKey, clk, clk.Add(time.Hour), nil), KeyPEM: pkcs8PEM(t, weak)}, "key"},
		{"P-521", ImportInput{IssuerID: iv.ID, CertPEM: ca.leaf(t, &p521.PublicKey, clk, clk.Add(time.Hour), nil), KeyPEM: pkcs8PEM(t, p521)}, "key"},
		{"ed25519", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: pkcs8PEM(t, edPriv)}, "key"},
		{"encrypted PKCS#8", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"}, "key"},
		{"encrypted legacy", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"}, "key"},
		{"corrupt key", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"}, "key"},
		{"oversized", ImportInput{IssuerID: iv.ID, CertPEM: strings.Repeat("a", MaxImportPEMBytes+1), KeyPEM: key}, "certificate"},
		{"oversized key", ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: strings.Repeat("a", MaxImportPEMBytes+1)}, "key"},
	}
	for _, c := range cases {
		var ve *ValidationError
		if _, err := f.svc.ImportACME(ctx, f.admin, c.in); !errors.As(err, &ve) || ve.Field != c.field {
			t.Errorf("%s: %v (want field %s)", c.name, err, c.field)
		}
	}
	if list, _ := f.mem.DueForRenewal(ctx, clk, clk.Add(10*365*24*time.Hour), 100); len(list) != 0 {
		t.Fatalf("refused imports stored %d rows", len(list))
	}
	// A caller without use on the issuer is refused.
	member := authz.Subjects{TenantID: f.admin.TenantID, UserID: "u-other", Roles: []string{"member"}}
	if _, err := f.svc.ImportACME(ctx, member, ImportInput{IssuerID: iv.ID, CertPEM: good, KeyPEM: key}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no use: %v", err)
	}
}
