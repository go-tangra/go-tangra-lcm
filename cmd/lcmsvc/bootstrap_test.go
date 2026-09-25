package main

import (
	"context"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/app"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// A trust domain change must not trip the per-tenant issuer name uniqueness:
// the second domain's default issuer gets its own name.
func TestEnsureDefaultIssuerAcrossTrustDomains(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	caIDs := map[string]string{}
	for _, td := range []string{"example.org", "infra.example.com"} {
		ca := store.CA{ID: store.NewID(), TenantID: app.MeshTenantID, TrustDomain: td, State: "active"}
		if err := st.InsertCA(ctx, ca); err != nil {
			t.Fatal(err)
		}
		caIDs[td] = ca.ID
	}
	for _, td := range []string{"example.org", "infra.example.com", "example.org", "infra.example.com"} {
		if err := ensureDefaultIssuer(ctx, st, td, caIDs[td]); err != nil {
			t.Fatalf("%s: %v", td, err)
		}
	}
	want := map[string]string{"example.org": "mesh", "infra.example.com": "mesh-infra.example.com"}
	for td, name := range want {
		def, err := st.DefaultIssuer(ctx, app.MeshTenantID, td)
		if err != nil {
			t.Fatalf("%s: %v", td, err)
		}
		if def.Name != name {
			t.Errorf("%s: issuer %q, want %q", td, def.Name, name)
		}
	}
}
