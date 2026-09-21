package security

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/secrets"
	"github.com/go-freya/freya/services/lcm/internal/store"
	"github.com/go-freya/freya/services/lcm/internal/transfer"
)

// forbidden are the substrings that must never appear in a listing, a
// credential-free export, an audit entry or any non-issuance response (SC-002).
var forbidden = []string{"PRIVATE KEY", "LCM-MARKER-SECRET", "LCM-MARKER-DNS"}

func scan(t *testing.T, what string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", what, err)
	}
	for _, bad := range forbidden {
		if strings.Contains(string(b), bad) {
			t.Fatalf("%s leaked %q:\n%s", what, bad, string(b))
		}
	}
}

// TestSC002_NoKeyMaterialAnywhere issues a certificate with a generated key,
// stores tenant secrets, and asserts that no key or secret material appears in
// certificate listings, downloads, issuer views, the credential-free backup
// export, or the audit trail. The one-time issuance bundle (which legitimately
// carries the generated key exactly once) is excluded.
func TestSC002_NoKeyMaterialAnywhere(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	setupIssuer(t, e.s)
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	aw := audit.NewWriter(e.st, nil)
	t.Cleanup(aw.Close)

	// A tenant secret whose value must never surface.
	sec := secrets.New(e.st, env, aw, nil)
	if _, err := sec.Create(ctx, admin(), secrets.Input{Name: "dns", Kind: "dns_credential", Value: sealed.Settings{"api_token": "LCM-MARKER-DNS-1"}}); err != nil {
		t.Fatal(err)
	}

	// Issue with a generated key (delivered once — the bundle itself is exempt).
	b, err := e.s.Issue(ctx, admin(), issue.IssueInput{SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600, DeliverKey: true})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(b.KeyPEM, "PRIVATE KEY") {
		t.Fatal("expected the generated key once at issuance")
	}

	// Certificate listing must carry no key material.
	list, _, err := e.s.ListCertificates(ctx, admin(), store.CertificateFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	scan(t, "certificate list", list)

	// Download must never include the key.
	dl, err := e.s.Download(ctx, admin(), b.Certificate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dl.KeyPEM != "" {
		t.Fatal("download returned a key")
	}
	scan(t, "download bundle", map[string]any{"cert": dl.CertPEM, "chain": dl.ChainPEM, "bundle": dl.BundlePEM})

	// Issuer view (credentials redacted).
	iv, err := e.s.GetIssuer(ctx, admin(), listIssuerID(t, e.s))
	if err != nil {
		t.Fatal(err)
	}
	scan(t, "issuer view", iv)

	// Secret list/view.
	secs, _ := sec.List(ctx, admin())
	scan(t, "secret list", secs)

	// Credential-free backup export.
	doc, err := transfer.New(e.st, env, aw, func() time.Time { return time.Unix(1700000000, 0) }).Export(ctx, admin(), false)
	if err != nil {
		t.Fatal(err)
	}
	scan(t, "backup export (no creds)", doc)

	// Audit trail.
	aw.Flush(ctx)
	rows, err := e.st.QueryAudit(ctx, tenant, store.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	scan(t, "audit trail", rows)
}
