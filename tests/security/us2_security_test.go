package security

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
)

// TestUS2_EntitlementMatrix: a viewer reads but cannot revoke; a caller with no
// share cannot grant; a cross-tenant caller sees nothing (not_found masking).
func TestUS2_EntitlementMatrix(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	setupIssuer(t, e.s)
	b, err := e.s.Issue(ctx, admin(), issue.IssueInput{SpiffeID: "spiffe://example.org/svc/api", ValiditySeconds: 3600})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	certID := b.Certificate.ID

	// Admin grants the viewer read-only on the certificate.
	if _, err := e.az.Grant(ctx, admin(), authz.GrantInput{ResourceType: authz.Certificate, ResourceID: certID, SubjectType: authz.SubjectUser, SubjectID: viewer().UserID, Relation: authz.Viewer}); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}
	if _, err := e.s.GetCertificate(ctx, viewer(), certID); err != nil {
		t.Fatalf("viewer read: %v", err)
	}
	if err := e.s.Revoke(ctx, viewer(), certID, "cessationOfOperation"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer revoke must be forbidden, got %v", err)
	}
	// The viewer holds no share, so cannot grant.
	if _, err := e.az.Grant(ctx, viewer(), authz.GrantInput{ResourceType: authz.Certificate, ResourceID: certID, SubjectType: authz.SubjectUser, SubjectID: "55555555-5555-7555-8555-555555555555", Relation: authz.Viewer}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer grant must be forbidden, got %v", err)
	}
	// Cross-tenant read is masked as not_found (never forbidden).
	other := authz.Subjects{TenantID: "99999999-9999-7999-8999-999999999999", UserID: "z", Roles: []string{"admin"}}
	if _, err := e.s.GetCertificate(ctx, other, certID); !errors.Is(err, authz.ErrNotFound) {
		t.Fatalf("cross-tenant read must be not_found, got %v", err)
	}
}
