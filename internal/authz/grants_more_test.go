package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// TestListGrants exercises the three ListGrants branches: resolve failure
// (masked as not-found), forbidden without share, and the success path that
// returns every grant on the resource.
func TestListGrants(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Unknown resource is masked as ErrNotFound by resolve.
	if _, err := f.az.ListGrants(ctx, user(uB), Certificate, store.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("list unknown: %v", err)
	}

	// A viewer holds no share: forbidden.
	f.grant(t, Certificate, f.cert, SubjectUser, uB, Viewer, nil)
	if _, err := f.az.ListGrants(ctx, user(uB), Certificate, f.cert); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer lists grants: %v", err)
	}

	// An owner holds share: sees every grant on the resource.
	must(t, f.az.GrantOwner(ctx, tA, Certificate, f.cert, uA))
	gs, err := f.az.ListGrants(ctx, user(uA), Certificate, f.cert)
	must(t, err)
	if len(gs) != 2 {
		t.Fatalf("owner list grants: got %d want 2", len(gs))
	}

	// The store error on the final read propagates (not masked).
	f.fs.FailOn("GrantsOnResource", errors.New("db"))
	if _, err := f.az.ListGrants(ctx, user(uA), Certificate, f.cert); err == nil {
		t.Fatal("list store error swallowed")
	}
	f.fs.FailOn("GrantsOnResource", nil)
}
