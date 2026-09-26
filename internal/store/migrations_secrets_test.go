package store

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
)

// The redaction migration must cover every DNS provider secret field.
func TestRedactMigrationCoversProviderSecrets(t *testing.T) {
	b, err := migrations.ReadFile("migrations/0007_redact_provider_secrets.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range append([]string{"acme_account_key", "dns_credential", "eab_hmac_key"}, acme.SecretFieldKeys()...) {
		if !strings.Contains(string(b), "'"+k+"'") {
			t.Errorf("migration does not redact %q", k)
		}
	}
}
