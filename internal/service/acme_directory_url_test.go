package service

import "testing"

func TestResolveACMEDirectoryURL(t *testing.T) {
	const endpoint = "https://acme-v02.api.letsencrypt.org/directory"
	const orderURL = "https://one.digicert.com/mpki/api/v1/acme/v2/directory?action=renew&orderId=1285184467"

	tests := []struct {
		name     string
		endpoint string
		override string
		want     string
	}{
		{"no override uses issuer endpoint", endpoint, "", endpoint},
		{"override wins", endpoint, orderURL, orderURL},
		{"whitespace-only override is ignored", endpoint, "   ", endpoint},
		{"override trims to a real value", endpoint, "  " + orderURL + "  ", "  " + orderURL + "  "},
		{"empty endpoint with override", "", orderURL, orderURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveACMEDirectoryURL(tt.endpoint, tt.override); got != tt.want {
				t.Errorf("resolveACMEDirectoryURL(%q, %q) = %q, want %q", tt.endpoint, tt.override, got, tt.want)
			}
		})
	}
}
