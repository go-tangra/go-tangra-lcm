package fuzz

import (
	"testing"

	"github.com/go-freya/freya/services/lcm/internal/transfer"
	"github.com/go-freya/freya/services/lcm/internal/webhook"
)

// FuzzWebhookSig: the HMAC signer never panics and always returns the sha256=
// prefix for any secret/payload.
func FuzzWebhookSig(f *testing.F) {
	f.Add([]byte("secret"), []byte(`{"event":"certificate.issued"}`))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("k"), make([]byte, 70000))
	f.Fuzz(func(t *testing.T, secret, payload []byte) {
		sig := webhook.Sign(secret, payload)
		if len(sig) < len("sha256=") || sig[:7] != "sha256=" {
			t.Fatalf("bad signature format: %q", sig)
		}
	})
}

// FuzzBackup: the backup parser never panics; oversize input is reported as
// such and anything accepted is version 1.
func FuzzBackup(f *testing.F) {
	f.Add(`{"version":1,"exported_at":"2026-01-01T00:00:00Z","tenant":"t","issuers":[],"certificates":[],"permissions":[]}`)
	f.Add(`{"version":"1"}`)
	f.Add(`[[[[[[[[[[]]]]]]]]]]`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		doc, err := transfer.DecodeBounded([]byte(raw))
		if err != nil {
			return
		}
		if doc.Version != 1 {
			t.Fatalf("accepted version %d", doc.Version)
		}
	})
}
