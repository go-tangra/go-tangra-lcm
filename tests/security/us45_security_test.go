package security

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/transfer"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
)

const marker = "LCM-MARKER-SECRET-VALUE"

// TestSR001_SecretAndWebhookSecretNeverLeak: a tenant-secret value and a
// webhook signing secret are write-only and never appear in any list/get view.
func TestSR001_SecretAndWebhookSecretNeverLeak(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	aw := audit.NewWriter(e.st, nil)
	t.Cleanup(aw.Close)
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))

	sec := secrets.New(e.st, env, aw, func() time.Time { return time.Unix(1700000000, 0) })
	sv, err := sec.Create(ctx, admin(), secrets.Input{Name: "acme", Kind: "acme_account", Value: sealed.Settings{"token": marker}})
	if err != nil {
		t.Fatalf("create secret: %v", err)
	}
	blob, _ := json.Marshal(sv)
	if strings.Contains(string(blob), marker) {
		t.Fatal("secret value leaked in create view")
	}
	list, _ := sec.List(ctx, admin())
	lb, _ := json.Marshal(list)
	if strings.Contains(string(lb), marker) {
		t.Fatal("secret value leaked in list")
	}
	// but the server-side accessor can open it
	val, err := sec.OpenValue(ctx, tenant, sv.ID)
	if err != nil || val["token"] != marker {
		t.Fatalf("OpenValue: %v %v", err, val)
	}

	wh := webhook.New(e.st, env, aw, func() time.Time { return time.Unix(1700000000, 0) })
	wv, err := wh.Create(ctx, admin(), webhook.Input{Name: "hook", URL: "https://example.test/hook", EventTypes: []string{webhook.EventIssued}, Secret: marker})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	wb, _ := json.Marshal(wv)
	if strings.Contains(string(wb), marker) {
		t.Fatal("webhook secret leaked in view")
	}
}

// TestSC002_CredentialFreeExportNoKeyMaterial: a credential-free backup export
// contains no private-key or secret material.
func TestSC002_CredentialFreeExportNoKeyMaterial(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	setupIssuer(t, e.s)
	aw := audit.NewWriter(e.st, nil)
	t.Cleanup(aw.Close)
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	// seed a tenant secret so the export must exclude it without credentials
	sec := secrets.New(e.st, env, aw, nil)
	if _, err := sec.Create(ctx, admin(), secrets.Input{Name: "dns", Kind: "dns_credential", Value: sealed.Settings{"api_token": marker}}); err != nil {
		t.Fatal(err)
	}
	xfer := transfer.New(e.st, env, aw, func() time.Time { return time.Unix(1700000000, 0) })
	doc, err := xfer.Export(ctx, admin(), false)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	blob, _ := json.Marshal(doc)
	for _, bad := range []string{marker, "PRIVATE KEY", sealed.Marker} {
		if strings.Contains(string(blob), bad) {
			t.Fatalf("credential-free export leaked %q", bad)
		}
	}
}
