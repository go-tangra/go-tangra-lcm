package service

import (
	"testing"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

func TestCnMatchesModule(t *testing.T) {
	const (
		server = commonV1.CertificateKind_CERTIFICATE_KIND_SERVER
		client = commonV1.CertificateKind_CERTIFICATE_KIND_CLIENT
	)
	tests := []struct {
		name    string
		module  string
		kind    commonV1.CertificateKind
		cn      string
		extra   []string
		want    bool
	}{
		{"server convention", "warden", server, "warden-service", nil, true},
		{"client convention", "warden", client, "lcm-warden", nil, true},
		{"cross-identity spoof rejected", "warden", client, "lcm-admin", nil, false},
		{"server CN on client kind rejected", "warden", client, "warden-service", nil, false},
		{"wrong module rejected", "warden", server, "backup-service", nil, false},
		{"extra allow-listed CN accepted", "lcm", server, "lcm-server", []string{"lcm-server"}, true},
		{"extra list does not open others", "warden", client, "lcm-admin", []string{"lcm-server"}, false},
		{"empty CN rejected", "warden", client, "", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cnMatchesModule(tc.module, tc.kind, tc.cn, tc.extra); got != tc.want {
				t.Fatalf("cnMatchesModule(%q, %v, %q, %v) = %v, want %v",
					tc.module, tc.kind, tc.cn, tc.extra, got, tc.want)
			}
		})
	}
}
