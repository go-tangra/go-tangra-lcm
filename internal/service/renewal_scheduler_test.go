package service

import (
	"reflect"
	"testing"
)

func TestRenewalIdentity(t *testing.T) {
	tests := []struct {
		name         string
		certCN       string
		sans         []string
		wantCN       string
		wantDNSNames []string
	}{
		{
			name:         "apex CN with wildcard SAN — CN must be preserved and added to SANs",
			certCN:       "itjobs.com",
			sans:         []string{"*.itjobs.com"},
			wantCN:       "itjobs.com",
			wantDNSNames: []string{"itjobs.com", "*.itjobs.com"},
		},
		{
			name:         "CN already present in SANs — SAN list unchanged",
			certCN:       "itjobs.com",
			sans:         []string{"itjobs.com", "*.itjobs.com"},
			wantCN:       "itjobs.com",
			wantDNSNames: []string{"itjobs.com", "*.itjobs.com"},
		},
		{
			name:         "wildcard-only cert — no spurious apex injected",
			certCN:       "*.itjobs.com",
			sans:         []string{"*.itjobs.com"},
			wantCN:       "*.itjobs.com",
			wantDNSNames: []string{"*.itjobs.com"},
		},
		{
			name:         "empty CN — fall back to first SAN (legacy behaviour)",
			certCN:       "",
			sans:         []string{"example.com", "www.example.com"},
			wantCN:       "example.com",
			wantDNSNames: []string{"example.com", "www.example.com"},
		},
		{
			name:         "whitespace-only CN — fall back to first SAN",
			certCN:       "   ",
			sans:         []string{"example.com"},
			wantCN:       "example.com",
			wantDNSNames: []string{"example.com"},
		},
		{
			name:         "empty everything — both empty",
			certCN:       "",
			sans:         nil,
			wantCN:       "",
			wantDNSNames: nil,
		},
		{
			name:         "CN preserved even when SANs are completely different",
			certCN:       "primary.example.com",
			sans:         []string{"alias-a.example.com", "alias-b.example.com"},
			wantCN:       "primary.example.com",
			wantDNSNames: []string{"primary.example.com", "alias-a.example.com", "alias-b.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCN, gotDNS := renewalIdentity(tc.certCN, tc.sans)
			if gotCN != tc.wantCN {
				t.Errorf("CN = %q, want %q", gotCN, tc.wantCN)
			}
			if !reflect.DeepEqual(gotDNS, tc.wantDNSNames) {
				t.Errorf("DNSNames = %v, want %v", gotDNS, tc.wantDNSNames)
			}
		})
	}
}

// TestRenewalIdentity_RegressionItjobsCom locks in the specific production
// scenario the fix was written for: a cert issued with CN=itjobs.com and
// SAN=*.itjobs.com (apex only in the CN). Before the fix, force-renew
// produced a CSR with CN=*.itjobs.com and the apex was lost.
func TestRenewalIdentity_RegressionItjobsCom(t *testing.T) {
	cn, dns := renewalIdentity("itjobs.com", []string{"*.itjobs.com"})
	if cn != "itjobs.com" {
		t.Errorf("regression: renewal CN = %q, want apex %q", cn, "itjobs.com")
	}
	if len(dns) != 2 || dns[0] != "itjobs.com" || dns[1] != "*.itjobs.com" {
		t.Errorf("regression: renewal DNSNames = %v, want [itjobs.com *.itjobs.com]", dns)
	}
}
