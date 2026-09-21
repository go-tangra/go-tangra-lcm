package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"

	acmeKey   = "SECRET-ACME-KEY-1"
	dnsToken  = "SECRET-DNS-TOKEN-1"
	keyPEM    = "-----BEGIN PRIVATE KEY-----\nSEALED-PRIVATE-KEY-MATERIAL\n-----END PRIVATE KEY-----"
	certPEMv  = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----"
	chainPEMv = "-----BEGIN CERTIFICATE-----\nYmFy\n-----END CERTIFICATE-----"
)

var seedSecretFields = []string{"acme_account_key", "dns_credential"}

func subj(tenant string) authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: uA, Roles: []string{"admin"}}
}

type fx struct {
	ms  *memstore.Mem
	env *sealed.Envelope
	aw  *audit.Writer
	svc *Service
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ms := memstore.New()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	svc := New(ms, env, aw, func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	return &fx{ms: ms, env: env, aw: aw, svc: svc}
}

func (f *fx) sealSettings(t *testing.T, ad []byte, s sealed.Settings) []byte {
	t.Helper()
	clear, err := sealed.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := f.env.Seal(clear, ad)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func (f *fx) seedIssuer(t *testing.T, tenant, name, typ, td string, def bool, settings, creds sealed.Settings) string {
	t.Helper()
	id := store.NewID()
	full := sealed.Settings{}
	for k, v := range settings {
		full[k] = v
	}
	for k, v := range creds {
		full[k] = v
	}
	public, err := sealed.Encode(sealed.Redact(full, seedSecretFields))
	if err != nil {
		t.Fatal(err)
	}
	row := store.Issuer{
		ID: id, TenantID: tenant, Name: name, Type: typ, TrustDomain: td, IsDefault: def,
		SettingsPublic: public, SettingsSealed: f.sealSettings(t, sealed.ADIssuer(id), full), Enabled: true,
	}
	if err := f.ms.InsertIssuer(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) seedCert(t *testing.T, tenant, issuerID, serial, spiffe string) string {
	t.Helper()
	id := store.NewID()
	sans, _ := json.Marshal([]string{spiffe})
	row := store.IssuedCertificate{
		ID: id, TenantID: tenant, IssuerID: issuerID, Serial: serial, SpiffeID: spiffe, Subject: "CN=" + spiffe,
		SANs: sans, NotBefore: time.Unix(1_699_000_000, 0).UTC(), NotAfter: time.Unix(1_699_900_000, 0).UTC(),
		FingerprintSHA256: "ab12", Status: "active", CertPEM: certPEMv, ChainPEM: chainPEMv,
		Owner: spiffe, KeySealed: []byte(keyPEM),
	}
	if err := f.ms.InsertCertificate(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) seedGrant(t *testing.T, tenant, resourceType, resourceID string) {
	t.Helper()
	by := uA
	_, err := f.ms.UpsertGrant(context.Background(), store.Grant{
		ID: store.NewID(), TenantID: tenant, ResourceType: resourceType, ResourceID: resourceID,
		SubjectType: authz.SubjectUser, SubjectID: uA, Relation: authz.Owner, GrantedBy: &by,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fx) seedSecret(t *testing.T, tenant, name, kind string, value sealed.Settings) {
	t.Helper()
	id := store.NewID()
	row := store.TenantSecret{ID: id, TenantID: tenant, Name: name, Kind: kind, ValueSealed: f.sealSettings(t, sealed.ADSecret(id), value)}
	if err := f.ms.InsertSecret(context.Background(), row); err != nil {
		t.Fatal(err)
	}
}

// seed populates tenant tA with two issuers, a certificate, two grants and a secret.
func (f *fx) seed(t *testing.T) (acmeID, selfID, certID string) {
	acmeID = f.seedIssuer(t, tA, "ACME", "acme", "example.org", false,
		sealed.Settings{"profile": "web"}, sealed.Settings{"acme_account_key": acmeKey})
	selfID = f.seedIssuer(t, tA, "Root", "self_signed", "internal", true, sealed.Settings{}, nil)
	certID = f.seedCert(t, tA, acmeID, "0A0B0C", "spiffe://example.org/svc")
	f.seedGrant(t, tA, authz.Issuer, acmeID)
	f.seedGrant(t, tA, authz.Certificate, certID)
	f.seedSecret(t, tA, "acme-account", "acme_account", sealed.Settings{"token": dnsToken})
	return
}

func auditCount(t *testing.T, ms *memstore.Mem, tenant, evt string) int {
	t.Helper()
	rows, err := ms.QueryAudit(context.Background(), tenant, store.AuditFilter{EventType: evt, To: time.Now().Add(time.Hour), Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestExportRedactsUnlessAsked(t *testing.T) {
	f := newFx(t)
	f.seed(t)
	ctx := context.Background()

	doc, err := f.svc.Export(ctx, subj(tA), false)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || doc.IncludesCredentials || doc.Tenant != tA {
		t.Fatalf("header: %+v", doc)
	}
	if len(doc.Issuers) != 2 || len(doc.Certificates) != 1 || len(doc.Permissions) != 2 || doc.Secrets != nil {
		t.Fatalf("counts: %+v", doc)
	}
	raw, _ := json.Marshal(doc)
	for _, forbidden := range []string{acmeKey, dnsToken, "PRIVATE KEY", "SEALED-PRIVATE-KEY", sealed.Marker, `"credentials"`, `"tenant_secrets"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("credential-free export leaks %q: %s", forbidden, raw)
		}
	}
	// The public certificate PEM is metadata and travels.
	if !strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatal("cert_pem missing from export")
	}
	for _, iss := range doc.Issuers {
		if iss.Credentials != nil {
			t.Fatalf("issuer %s carries credentials without request", iss.Name)
		}
	}

	// With credentials the secret values and issuer credentials are present.
	full, err := f.svc.Export(ctx, subj(tA), true)
	if err != nil || !full.IncludesCredentials {
		t.Fatalf("with credentials: %v %+v", err, full)
	}
	var acme *Issuer
	for i := range full.Issuers {
		if full.Issuers[i].Name == "ACME" {
			acme = &full.Issuers[i]
		}
	}
	if acme == nil || acme.Credentials["acme_account_key"] != acmeKey {
		t.Fatalf("issuer credential not exported: %+v", acme)
	}
	if len(full.Secrets) != 1 || !strings.Contains(full.Secrets[0].Value, dnsToken) {
		t.Fatalf("secret value not exported: %+v", full.Secrets)
	}
	// A with-credentials document validates against the schema when re-encoded.
	raw, _ = json.Marshal(full)
	if _, err := DecodeBounded(raw); err != nil {
		t.Fatalf("schema round-trip: %v", err)
	}

	f.aw.Flush(ctx)
	if auditCount(t, f.ms, tA, "backup_exported") != 1 || auditCount(t, f.ms, tA, "backup_exported_with_credentials") != 1 {
		t.Fatal("audit events missing")
	}

	for _, op := range []string{"ListIssuers", "ListCertificates", "ListSecrets"} {
		f.ms.FailOn(op, errors.New("down"))
		if _, err := f.svc.Export(ctx, subj(tA), true); err == nil {
			t.Errorf("%s outage not surfaced", op)
		}
		f.ms.FailOn(op, nil)
	}
}

func TestDecodeBounded(t *testing.T) {
	if _, err := DecodeBounded(bytes.Repeat([]byte("a"), MaxBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	deep := strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)
	if _, err := DecodeBounded([]byte(deep)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "deep") {
		t.Fatalf("deep: %v", err)
	}
	if _, err := DecodeBounded([]byte(`{"version":`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	// version must be 1 (schema const).
	if _, err := DecodeBounded([]byte(`{"version":2,"exported_at":"2024-01-01T00:00:00Z","tenant":"t","issuers":[],"certificates":[],"permissions":[]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad version: %v", err)
	}
	// unknown top-level field (additionalProperties:false).
	if _, err := DecodeBounded([]byte(`{"version":1,"exported_at":"2024-01-01T00:00:00Z","tenant":"t","issuers":[],"certificates":[],"permissions":[],"extra":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extra field: %v", err)
	}
	// too many issuers (schema maxItems 1000).
	items := make([]string, 0, 1001)
	for i := 0; i <= 1000; i++ {
		items = append(items, `{"name":"i","type":"acme","trust_domain":"d"}`)
	}
	big := `{"version":1,"exported_at":"2024-01-01T00:00:00Z","tenant":"t","issuers":[` + strings.Join(items, ",") + `],"certificates":[],"permissions":[]}`
	if _, err := DecodeBounded([]byte(big)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many issuers: %v", err)
	}
	// a valid minimal document decodes.
	doc, err := DecodeBounded([]byte(`{"version":1,"exported_at":"2024-01-01T00:00:00Z","tenant":"t","includes_credentials":false,"issuers":[{"name":"a","type":"acme","trust_domain":"d","settings":{"x":"y"}}],"certificates":[],"permissions":[]}`))
	if err != nil || len(doc.Issuers) != 1 || doc.Issuers[0].Type != "acme" {
		t.Fatalf("valid decode: %v %+v", err, doc)
	}
	if firstLine("a\nb") != "a" || firstLine("a") != "a" {
		t.Fatal("firstLine")
	}
	if d := depth([]byte(`{"a":"}{[","b":[[{}]]}`)); d != 4 {
		t.Fatalf("depth %d", d)
	}
}

func TestImportRoundTrip(t *testing.T) {
	src := newFx(t)
	src.seed(t)
	ctx := context.Background()
	doc, err := src.svc.Export(ctx, subj(tA), true)
	if err != nil {
		t.Fatal(err)
	}

	// Import into a fresh tenant/store.
	dst := newFx(t)
	if _, err := dst.svc.Import(ctx, subj(tB), doc, "merge"); !errors.Is(err, ErrMode) {
		t.Fatalf("bad mode: %v", err)
	}
	rep, err := dst.svc.Import(ctx, subj(tB), doc, "skip")
	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuersCreated != 2 || rep.CertificatesCreated != 1 || rep.GrantsCreated != 2 || rep.SecretsCreated != 1 {
		t.Fatalf("round-trip report: %+v", rep)
	}
	if len(dst.ms.Issuers) != 2 || len(dst.ms.Certificates) != 1 || len(dst.ms.Grants) != 2 || len(dst.ms.Secrets) != 1 {
		t.Fatalf("store not populated: issuers=%d certs=%d grants=%d secrets=%d",
			len(dst.ms.Issuers), len(dst.ms.Certificates), len(dst.ms.Grants), len(dst.ms.Secrets))
	}

	// Credentials travelled: the imported ACME issuer resolves its account key.
	issuers, _ := dst.ms.ListIssuers(ctx, tB, "", 100)
	var acmeID string
	for _, i := range issuers {
		if i.Name == "ACME" {
			acmeID = i.ID
		}
	}
	row, _ := dst.ms.GetIssuer(ctx, tB, acmeID)
	clear, err := dst.env.Open(row.SettingsSealed, sealed.ADIssuer(acmeID))
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := sealed.Decode(clear)
	if settings["acme_account_key"] != acmeKey || settings["profile"] != "web" {
		t.Fatalf("issuer credential not re-sealed: %+v", settings)
	}
	// Secret value travelled.
	sec, err := dst.ms.SecretByName(ctx, tB, "acme-account")
	if err != nil {
		t.Fatal(err)
	}
	sclear, err := dst.env.Open(sec.ValueSealed, sealed.ADSecret(sec.ID))
	if err != nil {
		t.Fatal(err)
	}
	sval, _ := sealed.Decode(sclear)
	if sval["token"] != dnsToken {
		t.Fatalf("secret value not re-sealed: %+v", sval)
	}
	// No private key travels: the imported certificate carries no sealed key.
	certs, _ := dst.ms.ListCertificates(ctx, tB, store.CertificateFilter{Limit: 10})
	if len(certs) != 1 || certs[0].KeySealed != nil || certs[0].Serial != "0A0B0C" {
		t.Fatalf("certificate: %+v", certs)
	}

	dst.aw.Flush(ctx)
	if auditCount(t, dst.ms, tB, "backup_imported") != 1 {
		t.Fatal("backup_imported not audited")
	}
}

func TestImportModes(t *testing.T) {
	src := newFx(t)
	src.seed(t)
	ctx := context.Background()
	doc, _ := src.svc.Export(ctx, subj(tA), true)

	dst := newFx(t)
	if _, err := dst.svc.Import(ctx, subj(tB), doc, "skip"); err != nil {
		t.Fatal(err)
	}
	// Second skip import leaves every duplicate untouched.
	rep, err := dst.svc.Import(ctx, subj(tB), doc, "skip")
	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuersCreated != 0 || rep.IssuersSkipped != 2 || rep.CertificatesSkipped != 1 || rep.SecretsCreated != 0 {
		t.Fatalf("skip report: %+v", rep)
	}
	if len(dst.ms.Issuers) != 2 || len(dst.ms.Secrets) != 1 {
		t.Fatal("skip mutated the store")
	}

	// Overwrite with a credential-free document changes public settings but
	// preserves the stored credential.
	pub, _ := src.svc.Export(ctx, subj(tA), false)
	for i := range pub.Issuers {
		if pub.Issuers[i].Name == "ACME" {
			pub.Issuers[i].Settings = sealed.Settings{"profile": "changed"}
		}
	}
	rep, err = dst.svc.Import(ctx, subj(tB), pub, "overwrite")
	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuersCreated != 2 || rep.IssuersSkipped != 0 {
		t.Fatalf("overwrite report: %+v", rep)
	}
	issuers, _ := dst.ms.ListIssuers(ctx, tB, "", 100)
	var acmeID string
	for _, i := range issuers {
		if i.Name == "ACME" {
			acmeID = i.ID
		}
	}
	row, _ := dst.ms.GetIssuer(ctx, tB, acmeID)
	public, _ := sealed.Decode(row.SettingsPublic)
	if public["profile"] != "changed" {
		t.Fatalf("overwrite did not apply public settings: %+v", public)
	}
	clear, _ := dst.env.Open(row.SettingsSealed, sealed.ADIssuer(acmeID))
	settings, _ := sealed.Decode(clear)
	if settings["acme_account_key"] != acmeKey {
		t.Fatalf("overwrite lost the stored credential: %+v", settings)
	}

	// Import bounds the item count.
	toobig := &Document{Version: 1, Issuers: make([]Issuer, maxIssuers+1)}
	if _, err := dst.svc.Import(ctx, subj(tB), toobig, "skip"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("item bound: %v", err)
	}
	// A store outage surfaces.
	dst.ms.FailOn("Atomic", errors.New("down"))
	if _, err := dst.svc.Import(ctx, subj(tB), doc, "skip"); err == nil {
		t.Error("atomic outage not surfaced")
	}
	dst.ms.FailOn("Atomic", nil)
}

func TestImportEdgeCases(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	nb := time.Unix(1_699_000_000, 0).UTC()
	na := time.Unix(1_699_900_000, 0).UTC()
	doc := &Document{
		Version: 1, IncludesCredentials: true,
		Issuers: []Issuer{{Name: "Only", Type: "acme", TrustDomain: "d", Settings: sealed.Settings{"a": "b"}, Credentials: sealed.Settings{"acme_account_key": "K"}}},
		Certificates: []Certificate{
			{Serial: "S1", SpiffeID: "spiffe://d/x", Issuer: "Only", NotBefore: nb, NotAfter: na, Status: "active"},
			{Serial: "S2", SpiffeID: "spiffe://d/y", Issuer: "Missing", NotBefore: nb, NotAfter: na, Status: "active"},
		},
		Permissions: []Permission{
			{ResourceType: "issuer", ResourceRef: "Only", SubjectType: "tenant", Relation: "viewer"},
			{ResourceType: "certificate", ResourceRef: "S1", SubjectType: "user", SubjectID: uA, Relation: "owner"},
			{ResourceType: "issuer", ResourceRef: "Ghost", SubjectType: "tenant", Relation: "viewer"},
			{ResourceType: "certificate", ResourceRef: "S9", SubjectType: "tenant", Relation: "viewer"},
		},
		Secrets: []Secret{{Name: "sec", Kind: "dns_credential", Value: `{"token":"T1"}`}},
	}
	rep, err := f.svc.Import(ctx, subj(tA), doc, "overwrite")
	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuersCreated != 1 || rep.CertificatesCreated != 1 || rep.CertificatesSkipped != 1 || rep.GrantsCreated != 2 || rep.SecretsCreated != 1 {
		t.Fatalf("edge report: %+v", rep)
	}

	// Re-import with overwrite updates the existing secret without recreating it.
	doc.Secrets[0].Value = `{"token":"T2"}`
	rep, err = f.svc.Import(ctx, subj(tA), doc, "overwrite")
	if err != nil {
		t.Fatal(err)
	}
	if rep.SecretsCreated != 0 {
		t.Fatalf("overwrite recreated secret: %+v", rep)
	}
	sec, _ := f.ms.SecretByName(ctx, tA, "sec")
	clear, _ := f.env.Open(sec.ValueSealed, sealed.ADSecret(sec.ID))
	val, _ := sealed.Decode(clear)
	if val["token"] != "T2" {
		t.Fatalf("secret not overwritten: %+v", val)
	}
	// Skip mode leaves the existing secret alone.
	doc.Secrets[0].Value = `{"token":"T3"}`
	if _, err := f.svc.Import(ctx, subj(tA), doc, "skip"); err != nil {
		t.Fatal(err)
	}
	sec, _ = f.ms.SecretByName(ctx, tA, "sec")
	clear, _ = f.env.Open(sec.ValueSealed, sealed.ADSecret(sec.ID))
	val, _ = sealed.Decode(clear)
	if val["token"] != "T2" {
		t.Fatalf("skip mutated secret: %+v", val)
	}
}

func TestCredentialFreeReimportFabricatesNothing(t *testing.T) {
	src := newFx(t)
	src.seed(t)
	ctx := context.Background()
	pub, err := src.svc.Export(ctx, subj(tA), false)
	if err != nil {
		t.Fatal(err)
	}

	dst := newFx(t)
	rep, err := dst.svc.Import(ctx, subj(tB), pub, "skip")
	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuersCreated != 2 || rep.CertificatesCreated != 1 || rep.SecretsCreated != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if len(dst.ms.Secrets) != 0 {
		t.Fatal("secrets fabricated from a credential-free export")
	}
	// The imported ACME issuer holds no credential fields.
	issuers, _ := dst.ms.ListIssuers(ctx, tB, "", 100)
	for _, i := range issuers {
		clear, err := dst.env.Open(i.SettingsSealed, sealed.ADIssuer(i.ID))
		if err != nil {
			t.Fatal(err)
		}
		settings, _ := sealed.Decode(clear)
		for _, f := range seedSecretFields {
			if _, ok := settings[f]; ok {
				t.Fatalf("issuer %s fabricated credential field %s", i.Name, f)
			}
		}
	}
}
