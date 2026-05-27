package dns

import "testing"

func TestChallengeFQDN(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"apex", "factory.bg", "_acme-challenge.factory.bg"},
		{"wildcard", "*.factory.bg", "_acme-challenge.factory.bg"},
		{"trailing dot", "factory.bg.", "_acme-challenge.factory.bg"},
		{"wildcard trailing dot", "*.factory.bg.", "_acme-challenge.factory.bg"},
		{"subdomain", "sub.factory.bg", "_acme-challenge.sub.factory.bg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChallengeFQDN(tt.domain); got != tt.want {
				t.Errorf("ChallengeFQDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// TestChallengeFQDN_ApexAndWildcardCollapse documents the core property that
// lets the issuer clean a shared challenge name once: an apex and its wildcard
// resolve to the same FQDN.
func TestChallengeFQDN_ApexAndWildcardCollapse(t *testing.T) {
	if ChallengeFQDN("factory.bg") != ChallengeFQDN("*.factory.bg") {
		t.Fatal("apex and wildcard must map to the same challenge FQDN")
	}
}
