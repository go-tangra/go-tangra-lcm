package security

import (
	"context"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const tenant = "11111111-1111-7111-8111-111111111111"

// tenv is a service plus the authorizer and store behind it, for tests that
// need to grant relations directly.
type tenv struct {
	s  *issue.Service
	az *authz.Authorizer
	st *memstore.Mem
}

func newEnv(t *testing.T) tenv {
	t.Helper()
	st := memstore.New()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	az := authz.New(st)
	aw := audit.NewWriter(st, nil)
	t.Cleanup(aw.Close)
	return tenv{s: issue.New(st, ca.New(st, env), env, az, aw, nil), az: az, st: st}
}

// newService keeps the US1 tests terse.
func newService(t *testing.T) *issue.Service { return newEnv(t).s }

func admin() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

func stranger() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "33333333-3333-7333-8333-333333333333"}
}

func viewer() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "44444444-4444-7444-8444-444444444444"}
}

func storeFilter() store.CertificateFilter { return store.CertificateFilter{Limit: 100} }

// setupIssuer creates a self-signed issuer as an admin and returns its id.
func setupIssuer(t *testing.T, s *issue.Service) string {
	t.Helper()
	iv, err := s.CreateIssuer(context.Background(), admin(), issue.IssuerInput{
		Name: "root", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	return iv.ID
}

func listIssuerID(t *testing.T, s *issue.Service) string {
	t.Helper()
	items, _, err := s.ListIssuers(context.Background(), admin(), "", 10)
	if err != nil || len(items) == 0 {
		t.Fatalf("list issuers: %v", err)
	}
	return items[0].ID
}
