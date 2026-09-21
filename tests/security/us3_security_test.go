package security

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lcmv1 "github.com/go-freya/freya/services/lcm/api/proto/lcm/v1"
	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/grpcapi"
)

// TestSR003_ForgedOrAbsentGRPCIdentityRejected: a lcm.v1 call without a verified
// SPIFFE identity is refused with Unauthenticated before any work is done.
func TestSR003_ForgedOrAbsentGRPCIdentityRejected(t *testing.T) {
	svid := &grpcapi.SVIDServer{}
	_, err := svid.Issue(context.Background(), &lcmv1.IssueRequest{TenantId: tenant, SpiffeId: "spiffe://example.org/svc/api"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("absent identity must be Unauthenticated, got %v", err)
	}
	en := &grpcapi.EnrollmentServer{}
	_, err = en.Enroll(context.Background(), &lcmv1.EnrollRequest{TenantId: tenant, SpiffeId: "spiffe://example.org/svc/api"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("absent identity must be Unauthenticated, got %v", err)
	}
}

// singleUseVerifier authorises a token once, then rejects it (replay).
type singleUseVerifier struct{ used bool }

func (v *singleUseVerifier) VerifyEnrollment(_ context.Context, token string) (enroll.EnrollGrant, error) {
	if v.used {
		return enroll.EnrollGrant{}, errors.New("token already used")
	}
	v.used = true
	return enroll.EnrollGrant{TenantID: tenant, SpiffePaths: []string{"spiffe://example.org/svc/token"}}, nil
}

// TestSR002_EnrollmentTokenReplayRefused: a replayed enrollment token is refused
// (and a token that does not cover the requested id is forbidden).
func TestSR002_EnrollmentTokenReplayRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	setupIssuer(t, e.s)
	aw := audit.NewWriter(e.st, nil)
	t.Cleanup(aw.Close)
	v := &singleUseVerifier{}
	svc := enroll.New(e.st, e.s, e.az, aw, v, enroll.Config{AutoApprove: true}, func() time.Time { return time.Unix(1700000000, 0) })

	anon := authz.Subjects{TenantID: tenant}
	// First use of the token for its own id succeeds.
	if _, err := svc.Enroll(ctx, anon, enroll.EnrollInput{SpiffeID: "spiffe://example.org/svc/token", EnrollmentToken: "t1"}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// Replay is refused.
	if _, err := svc.Enroll(ctx, anon, enroll.EnrollInput{SpiffeID: "spiffe://example.org/svc/token", EnrollmentToken: "t1"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("replayed token must be forbidden, got %v", err)
	}
	// A fresh token that does not cover the requested id is forbidden.
	v2 := &singleUseVerifier{}
	svc2 := enroll.New(e.st, e.s, e.az, aw, v2, enroll.Config{AutoApprove: true}, nil)
	if _, err := svc2.Enroll(ctx, anon, enroll.EnrollInput{SpiffeID: "spiffe://example.org/svc/other", EnrollmentToken: "t2"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("token for wrong id must be forbidden, got %v", err)
	}
}
