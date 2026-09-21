package issue

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

var clk = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type fixture struct {
	mem   *memstore.Mem
	env   *sealed.Envelope
	auth  *ca.Authority
	az    *authz.Authorizer
	aw    *audit.Writer
	svc   *Service
	admin authz.Subjects
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	mem := memstore.New()
	mem.Now = func() time.Time { return clk }
	auth := ca.New(mem, env)
	auth.Clock = func() time.Time { return clk }
	az := authz.New(mem)
	az.SetClock(func() time.Time { return clk })
	aw := audit.NewWriter(mem, nil)
	t.Cleanup(aw.Close)
	svc := New(mem, auth, env, az, aw, func() time.Time { return clk })
	return &fixture{
		mem: mem, env: env, auth: auth, az: az, aw: aw, svc: svc,
		admin: authz.Subjects{TenantID: "t1", UserID: "u-admin", Roles: []string{"admin"}},
	}
}

func (f *fixture) audits(t *testing.T) []store.AuditRow {
	t.Helper()
	f.aw.Flush(context.Background())
	return append([]store.AuditRow(nil), f.mem.Audit...)
}

func mustIssuer(t *testing.T, f *fixture, name string, isDefault bool) IssuerView {
	t.Helper()
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: name, Type: "self_signed", TrustDomain: "example.org", IsDefault: isDefault, Enabled: true,
		Settings: sealed.Settings{"acme_account_key": "top-secret-value"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
	return iv
}

func makeCSR(t *testing.T, dns []string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{DNSNames: dns}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestCreateIssuerAutogeneratesCAAndRedacts(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)

	if iv.CAID == "" {
		t.Fatalf("expected a CA reference")
	}
	if len(f.mem.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(f.mem.CAs))
	}
	if got := iv.Settings["acme_account_key"]; got != sealed.Marker {
		t.Fatalf("secret not redacted: %v", got)
	}
	blob, _ := json.Marshal(iv)
	if bytes.Contains(blob, []byte("top-secret-value")) {
		t.Fatalf("secret value leaked into issuer view")
	}

	// A second issuer reuses the CA (EnsureCA).
	_ = mustIssuer(t, f, "secondary", false)
	if len(f.mem.CAs) != 1 {
		t.Fatalf("CA regenerated: %d", len(f.mem.CAs))
	}
}

func verifyChain(t *testing.T, certPEM, bundlePEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("cert not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundlePEM)) {
		t.Fatalf("bundle not added")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: clk, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("verify leaf: %v", err)
	}
	return leaf
}

func TestIssueFromCSR(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	csrPEM := makeCSR(t, []string{"svc.example.org"})

	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/workload", CSRPEM: csrPEM,
		DNSSans: []string{"svc.example.org"}, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if b.KeyPEM != "" {
		t.Fatalf("CSR issuance must not return a key")
	}
	leaf := verifyChain(t, b.CertPEM, b.BundlePEM)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://example.org/workload" {
		t.Fatalf("URI SAN = %v", leaf.URIs)
	}
	if b.Certificate.Status != "active" {
		t.Fatalf("status = %s", b.Certificate.Status)
	}
	// No private key material anywhere in the returned bundle.
	blob, _ := json.Marshal(b)
	if bytes.Contains(blob, []byte("PRIVATE KEY")) {
		t.Fatalf("private key material leaked in bundle")
	}
}

func TestIssueGeneratedKeyDeliveredOnce(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)

	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/db", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if b.KeyPEM == "" {
		t.Fatalf("expected a delivered key")
	}
	block, _ := pem.Decode([]byte(b.KeyPEM))
	if block == nil {
		t.Fatalf("key not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("delivered key not parseable: %v", err)
	}
	if !b.Certificate.KeyDelivered {
		t.Fatalf("expected key_delivered")
	}
	// Stored row must no longer carry the sealed key.
	stored := f.mem.Certificates[b.Certificate.ID]
	if stored.KeySealed != nil || !stored.KeyDelivered {
		t.Fatalf("sealed key not cleared after delivery")
	}
	// Download never returns the key again.
	dl, err := f.svc.Download(context.Background(), f.admin, b.Certificate.ID)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if dl.KeyPEM != "" {
		t.Fatalf("Download returned a key")
	}
}

func TestIssueValidityClampAndDefault(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)

	// Over-long request is clamped to the ceiling.
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/a", DeliverKey: true, ValiditySeconds: 100 * 365 * 24 * 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	want := clk.Add(time.Duration(MaxValiditySeconds) * time.Second)
	if !b.Certificate.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %v, want clamp %v", b.Certificate.NotAfter, want)
	}

	// Zero uses the default.
	b2, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/b", DeliverKey: true, ValiditySeconds: 0,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wantDef := clk.Add(time.Duration(DefaultValiditySeconds) * time.Second)
	if !b2.Certificate.NotAfter.Equal(wantDef) {
		t.Fatalf("NotAfter = %v, want default %v", b2.Certificate.NotAfter, wantDef)
	}
}

func TestIssueSANEnforcement(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	// CSR carries a DNS SAN not present in the authorised set.
	csrPEM := makeCSR(t, []string{"evil.example.org"})
	_, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/x", CSRPEM: csrPEM, DNSSans: []string{"good.example.org"},
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "dns_sans" {
		t.Fatalf("want dns_sans ValidationError, got %v", err)
	}
}

func TestIssueTrustDomainMismatch(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	_, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://other.org/x", DeliverKey: true,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "spiffe_id" {
		t.Fatalf("want spiffe_id ValidationError, got %v", err)
	}
}

func TestIssueEntitlementRefused(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)

	// A user with no grants and no admin role is not entitled (SR-002).
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-stranger"}
	_, err := f.svc.Issue(context.Background(), stranger, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/x", DeliverKey: true,
	})
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}

	// A service caller may issue only its own identity.
	svcCaller := authz.ServiceSubjects("t1", "spiffe://example.org/api")
	if _, err := f.svc.Issue(context.Background(), svcCaller, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/api", DeliverKey: true,
	}); err != nil {
		t.Fatalf("service self-issuance should succeed: %v", err)
	}
	if _, err := f.svc.Issue(context.Background(), svcCaller, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/other", DeliverKey: true,
	}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("service cross-identity issuance want ErrForbidden, got %v", err)
	}
}

func TestRenewSupersedes(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	orig, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/renew", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	renewed, err := f.svc.Renew(context.Background(), f.admin, orig.Certificate.ID)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.Certificate.ID == orig.Certificate.ID {
		t.Fatalf("renew produced the same certificate")
	}
	if renewed.Certificate.Serial == orig.Certificate.Serial {
		t.Fatalf("renew reused the serial")
	}
	old := f.mem.Certificates[orig.Certificate.ID]
	if old.SupersededBy == nil || *old.SupersededBy != renewed.Certificate.ID {
		t.Fatalf("old cert not superseded: %+v", old.SupersededBy)
	}
	if renewed.Certificate.SpiffeID != "spiffe://example.org/renew" {
		t.Fatalf("renew changed the SPIFFE id")
	}
}

func TestRevokeSetsStatusAndRevocation(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/gone", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := f.svc.Revoke(context.Background(), f.admin, b.Certificate.ID, "keyCompromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	stored := f.mem.Certificates[b.Certificate.ID]
	if stored.Status != "revoked" {
		t.Fatalf("status = %s", stored.Status)
	}
	found := false
	for _, r := range f.mem.Revocations {
		if r.CertificateID == b.Certificate.ID {
			found = true
			if r.Reason != "keyCompromise" || r.Serial != stored.Serial {
				t.Fatalf("revocation fields = %+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("no revocation row inserted")
	}
	view, err := f.svc.GetCertificate(context.Background(), f.admin, b.Certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if view.Status != "revoked" {
		t.Fatalf("derived status = %s", view.Status)
	}
}

func TestDefaultIssuerUniqueness(t *testing.T) {
	f := newFixture(t)
	a := mustIssuer(t, f, "alpha", true)
	b := mustIssuer(t, f, "beta", true)

	defaults := 0
	for _, i := range f.mem.Issuers {
		if i.IsDefault {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("expected exactly 1 default issuer, got %d", defaults)
	}
	if f.mem.Issuers[a.ID].IsDefault {
		t.Fatalf("alpha should no longer be default")
	}
	if !f.mem.Issuers[b.ID].IsDefault {
		t.Fatalf("beta should be default")
	}
	def, err := f.mem.DefaultIssuer(context.Background(), "t1", "example.org")
	if err != nil || def.ID != b.ID {
		t.Fatalf("DefaultIssuer = %v, %v", def.ID, err)
	}
}

func TestIssuerNameUniquenessAndValidation(t *testing.T) {
	f := newFixture(t)
	_ = mustIssuer(t, f, "dup", false)

	_, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "dup", Type: "self_signed", TrustDomain: "example.org", Enabled: true,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "name" {
		t.Fatalf("want name ValidationError, got %v", err)
	}

	_, err = f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "", Type: "self_signed", TrustDomain: "example.org",
	})
	if !errors.As(err, &ve) || ve.Field != "name" {
		t.Fatalf("want empty-name ValidationError, got %v", err)
	}
}

func TestDeleteIssuerInUse(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	if _, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/held", DeliverKey: true, ValiditySeconds: 3600,
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	err := f.svc.DeleteIssuer(context.Background(), f.admin, iv.ID)
	var iu *InUseError
	if !errors.As(err, &iu) || iu.Count < 1 {
		t.Fatalf("want InUseError, got %v", err)
	}
}

func TestExpiringStatusDerivation(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	// Short-lived cert: 1 hour TTL, window = min(30d, 30min) = 30min, so at issue
	// time (t=0) it is active; advance the clock to within 30 min of expiry.
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/exp", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if b.Certificate.Status != "active" {
		t.Fatalf("fresh cert status = %s", b.Certificate.Status)
	}
	// Move clock to 50 minutes in (10 min to expiry) -> expiring.
	f.svc.SetClock(func() time.Time { return clk.Add(50 * time.Minute) })
	view, err := f.svc.GetCertificate(context.Background(), f.admin, b.Certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if view.Status != "expiring" {
		t.Fatalf("status = %s, want expiring", view.Status)
	}
	// Past not_after -> expired.
	f.svc.SetClock(func() time.Time { return clk.Add(2 * time.Hour) })
	view, _ = f.svc.GetCertificate(context.Background(), f.admin, b.Certificate.ID)
	if view.Status != "expired" {
		t.Fatalf("status = %s, want expired", view.Status)
	}
}

func TestListCertificatesAndIssuers(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	for _, p := range []string{"a", "b", "c"} {
		if _, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
			IssuerID: iv.ID, SpiffeID: "spiffe://example.org/" + p, DeliverKey: true, ValiditySeconds: 3600,
		}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	certs, _, err := f.svc.ListCertificates(context.Background(), f.admin, store.CertificateFilter{})
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(certs))
	}
	issuers, _, err := f.svc.ListIssuers(context.Background(), f.admin, "", 50)
	if err != nil {
		t.Fatalf("ListIssuers: %v", err)
	}
	if len(issuers) != 1 {
		t.Fatalf("expected 1 issuer, got %d", len(issuers))
	}
}

func TestUpdateIssuerKeepsSecret(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	// Update without resending the secret keeps it; the view stays redacted.
	got, err := f.svc.UpdateIssuer(context.Background(), f.admin, iv.ID, IssuerInput{
		Name: "primary", Enabled: false, Settings: sealed.Settings{"acme_account_key": sealed.Marker},
	})
	if err != nil {
		t.Fatalf("UpdateIssuer: %v", err)
	}
	if got.Enabled {
		t.Fatalf("expected disabled")
	}
	// The stored sealed settings must still open to the original secret.
	row := f.mem.Issuers[iv.ID]
	clear, err := f.env.Open(row.SettingsSealed, sealed.ADIssuer(iv.ID))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s, _ := sealed.Decode(clear)
	if s["acme_account_key"] != "top-secret-value" {
		t.Fatalf("secret not preserved: %v", s["acme_account_key"])
	}
}

func TestUpdateCertificateOwnerAndDelete(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/own", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	upd, err := f.svc.UpdateCertificate(context.Background(), f.admin, b.Certificate.ID, CertificateUpdate{Owner: "team-x"})
	if err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}
	if upd.Owner != "team-x" {
		t.Fatalf("owner = %s", upd.Owner)
	}
	if err := f.svc.DeleteCertificate(context.Background(), f.admin, b.Certificate.ID); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	if _, ok := f.mem.Certificates[b.Certificate.ID]; ok {
		t.Fatalf("certificate not deleted")
	}
}

func TestAuditTrail(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/aud", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := f.svc.Revoke(context.Background(), f.admin, b.Certificate.ID, "cessationOfOperation"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	types := map[string]bool{}
	for _, r := range f.audits(t) {
		types[r.EventType] = true
	}
	for _, want := range []string{"issuer_created", "certificate_issued", "certificate_revoked"} {
		if !types[want] {
			t.Fatalf("missing audit event %q in %v", want, types)
		}
	}
	// No key material or secret leaks into audit details.
	f.aw.Flush(context.Background())
	for _, r := range f.mem.Audit {
		if strings.Contains(string(r.Details), "top-secret-value") || strings.Contains(string(r.Details), "PRIVATE KEY") {
			t.Fatalf("secret leaked into audit details: %s", r.Details)
		}
	}
}

func TestDownloadForbiddenForStranger(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/priv", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-stranger"}
	if _, err := f.svc.Download(context.Background(), stranger, b.Certificate.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	// A different tenant sees not-found (masking existence).
	other := authz.Subjects{TenantID: "t2", UserID: "u2", Roles: []string{"admin"}}
	if _, err := f.svc.Download(context.Background(), other, b.Certificate.ID); !errors.Is(err, authz.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// url import guard: ensure the leaf URI round-trips through net/url as expected.
func TestSpiffeURIParses(t *testing.T) {
	u, err := url.Parse("spiffe://example.org/x")
	if err != nil || u.Scheme != "spiffe" {
		t.Fatalf("url parse: %v", err)
	}
}

func TestErrorStrings(t *testing.T) {
	if (&ValidationError{Field: "name", Message: "bad"}).Error() == "" {
		t.Fatal("empty ValidationError string")
	}
	if (&ValidationError{Message: "bad"}).Error() == "" {
		t.Fatal("empty fieldless ValidationError string")
	}
	if (&InUseError{What: "certificates", Count: 2}).Error() == "" {
		t.Fatal("empty InUseError string")
	}
}

func TestNewDefaultsClock(t *testing.T) {
	env, _ := sealed.NewEnvelope(bytes.Repeat([]byte{1}, 32))
	mem := memstore.New()
	s := New(mem, ca.New(mem, env), env, authz.New(mem), nil, nil)
	if s.now == nil {
		t.Fatal("clock not defaulted")
	}
}

func TestMarkKeyDeliveredDirect(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	// DeliverKey false: the key is generated, sealed and stored, not returned.
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/mk", DeliverKey: false, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if b.KeyPEM != "" {
		t.Fatalf("no key should be returned when DeliverKey is false")
	}
	if f.mem.Certificates[b.Certificate.ID].KeySealed == nil {
		t.Fatalf("expected a stored sealed key")
	}
	if err := f.svc.MarkKeyDelivered(context.Background(), f.admin, b.Certificate.ID); err != nil {
		t.Fatalf("MarkKeyDelivered: %v", err)
	}
	if f.mem.Certificates[b.Certificate.ID].KeySealed != nil {
		t.Fatalf("sealed key not cleared")
	}
}

func TestDeleteIssuerSuccess(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	if err := f.svc.DeleteIssuer(context.Background(), f.admin, iv.ID); err != nil {
		t.Fatalf("DeleteIssuer: %v", err)
	}
	if _, ok := f.mem.Issuers[iv.ID]; ok {
		t.Fatalf("issuer not deleted")
	}
}

func TestResolveIssuerDefaultAndNotFound(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)

	// No IssuerID -> default issuer resolved.
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		SpiffeID: "spiffe://example.org/def", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue via default: %v", err)
	}
	if b.Certificate.IssuerID != iv.ID {
		t.Fatalf("default issuer mismatch")
	}

	// Bad IssuerID -> ValidationError issuer_id.
	_, err = f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: "missing", SpiffeID: "spiffe://example.org/x", DeliverKey: true,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "issuer_id" {
		t.Fatalf("want issuer_id ValidationError, got %v", err)
	}

	// Bad SPIFFE id -> ValidationError spiffe_id.
	_, err = f.svc.Issue(context.Background(), f.admin, IssueInput{SpiffeID: "not-a-spiffe-id"})
	if !errors.As(err, &ve) || ve.Field != "spiffe_id" {
		t.Fatalf("want spiffe_id ValidationError, got %v", err)
	}

	// No default issuer for a fresh trust domain (still valid) -> issuer_id.
	_, err = f.svc.Issue(context.Background(), f.admin, IssueInput{SpiffeID: "spiffe://nodefault.org/x"})
	if !errors.As(err, &ve) || ve.Field != "issuer_id" {
		t.Fatalf("want issuer_id ValidationError for missing default, got %v", err)
	}
}

func TestClampValidityMinimum(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/min", DeliverKey: true, ValiditySeconds: 1,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	want := clk.Add(time.Duration(MinValiditySeconds) * time.Second)
	if !b.Certificate.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %v, want min clamp %v", b.Certificate.NotAfter, want)
	}
}

func TestCreateIssuerValidation(t *testing.T) {
	f := newFixture(t)
	var ve *ValidationError

	_, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{Name: "x", Type: "bogus", TrustDomain: "example.org"})
	if !errors.As(err, &ve) || ve.Field != "type" {
		t.Fatalf("want type ValidationError, got %v", err)
	}
	_, err = f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{Name: "x", Type: "self_signed", TrustDomain: "bad_domain"})
	if !errors.As(err, &ve) || ve.Field != "trust_domain" {
		t.Fatalf("want trust_domain ValidationError, got %v", err)
	}
	// Digits and hyphen are valid host characters.
	if _, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{Name: "ok", Type: "self_signed", TrustDomain: "ex-1.org", Enabled: true}); err != nil {
		t.Fatalf("valid domain rejected: %v", err)
	}
}

func TestMintNonSigningIssuer(t *testing.T) {
	f := newFixture(t)
	// An ACME issuer has no CA to sign with.
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "acme", Type: "acme", TrustDomain: "example.org", IsDefault: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
	_, err = f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/x", DeliverKey: true,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "issuer_id" {
		t.Fatalf("want issuer_id ValidationError for non-signing issuer, got %v", err)
	}
}

func TestUpdateIssuerDefaultAndTypeFixed(t *testing.T) {
	f := newFixture(t)
	a := mustIssuer(t, f, "alpha", true)
	b := mustIssuer(t, f, "beta", false)

	// Promote beta to default; alpha loses default.
	if _, err := f.svc.UpdateIssuer(context.Background(), f.admin, b.ID, IssuerInput{Name: "beta", IsDefault: true, Enabled: true}); err != nil {
		t.Fatalf("UpdateIssuer default: %v", err)
	}
	if f.mem.Issuers[a.ID].IsDefault {
		t.Fatalf("alpha should have lost default")
	}
	// The type cannot change.
	_, err := f.svc.UpdateIssuer(context.Background(), f.admin, b.ID, IssuerInput{Name: "beta", Type: "acme"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "type" {
		t.Fatalf("want type ValidationError, got %v", err)
	}
}

func TestForbiddenAndNotFoundPaths(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/z", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-stranger"}
	ctx := context.Background()

	if _, err := f.svc.GetCertificate(ctx, stranger, b.Certificate.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("GetCertificate want forbidden, got %v", err)
	}
	if _, err := f.svc.GetIssuer(ctx, stranger, iv.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("GetIssuer want forbidden, got %v", err)
	}
	if _, err := f.svc.UpdateCertificate(ctx, stranger, b.Certificate.ID, CertificateUpdate{Owner: "x"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("UpdateCertificate want forbidden, got %v", err)
	}
	if _, err := f.svc.UpdateIssuer(ctx, stranger, iv.ID, IssuerInput{Name: "primary"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("UpdateIssuer want forbidden, got %v", err)
	}
	if err := f.svc.DeleteIssuer(ctx, stranger, iv.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("DeleteIssuer want forbidden, got %v", err)
	}
	if err := f.svc.DeleteCertificate(ctx, stranger, b.Certificate.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("DeleteCertificate want forbidden, got %v", err)
	}
	if _, err := f.svc.Renew(ctx, stranger, b.Certificate.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("Renew want forbidden, got %v", err)
	}
	if err := f.svc.Revoke(ctx, stranger, b.Certificate.ID, "x"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("Revoke want forbidden, got %v", err)
	}
	if err := f.svc.MarkKeyDelivered(ctx, stranger, b.Certificate.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("MarkKeyDelivered want forbidden, got %v", err)
	}
}

func TestIssueMalformedCSR(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	_, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/x", CSRPEM: "-----BEGIN CERTIFICATE REQUEST-----\ngarbage\n-----END CERTIFICATE REQUEST-----\n",
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "csr" {
		t.Fatalf("want csr ValidationError, got %v", err)
	}
}

func TestListCertificatesScopedToGrants(t *testing.T) {
	f := newFixture(t)
	iv := mustIssuer(t, f, "primary", true)
	ctx := context.Background()
	var firstID string
	for i, p := range []string{"one", "two", "three"} {
		b, err := f.svc.Issue(ctx, f.admin, IssueInput{
			IssuerID: iv.ID, SpiffeID: "spiffe://example.org/" + p, DeliverKey: true, ValiditySeconds: 3600,
		})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if i == 0 {
			firstID = b.Certificate.ID
		}
	}
	// A non-admin user granted owner on only one certificate sees only that one.
	if err := f.az.GrantOwner(ctx, "t1", authz.Certificate, firstID, "u1"); err != nil {
		t.Fatalf("GrantOwner: %v", err)
	}
	user := authz.Subjects{TenantID: "t1", UserID: "u1"}
	certs, _, err := f.svc.ListCertificates(ctx, user, store.CertificateFilter{})
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 1 || certs[0].ID != firstID {
		t.Fatalf("scoped list = %d certs, want just the granted one", len(certs))
	}
	// Same for issuers.
	if err := f.az.GrantOwner(ctx, "t1", authz.Issuer, iv.ID, "u1"); err != nil {
		t.Fatalf("GrantOwner issuer: %v", err)
	}
	issuers, _, err := f.svc.ListIssuers(ctx, user, "", 50)
	if err != nil {
		t.Fatalf("ListIssuers: %v", err)
	}
	if len(issuers) != 1 {
		t.Fatalf("scoped issuer list = %d", len(issuers))
	}
}

func TestLongTrustDomainRejected(t *testing.T) {
	f := newFixture(t)
	long := strings.Repeat("a", 254)
	_, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{Name: "x", Type: "self_signed", TrustDomain: long})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "trust_domain" {
		t.Fatalf("want trust_domain ValidationError, got %v", err)
	}
}
