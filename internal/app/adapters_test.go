package app

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
)

// enrollClient answers VerifyEnrollmentToken with a fixed response or error.
type enrollClient struct {
	authv1.EnrollmentClient
	resp *authv1.VerifyEnrollmentTokenResponse
	err  error
}

func (c enrollClient) VerifyEnrollmentToken(context.Context, *authv1.VerifyEnrollmentTokenRequest, ...grpc.CallOption) (*authv1.VerifyEnrollmentTokenResponse, error) {
	return c.resp, c.err
}

// auth's Unauthenticated status message is its closed reason; lcm relays it
// (older auth messages and unknown text stay opaque), and any other status is
// no verdict on the token.
func TestAuthEnrollTokensReasons(t *testing.T) {
	ctx := context.Background()
	for msg, want := range map[string]string{
		"enrollment_token_expired":        enroll.ReasonTokenExpired,
		"enrollment_token_not_yet_valid":  enroll.ReasonTokenNotYetValid,
		"enrollment_token_used":           enroll.ReasonTokenUsed,
		"enrollment_token_invalid":        enroll.ReasonTokenInvalid,
		"enrollment token cannot be used": enroll.ReasonTokenUsed,
		"invalid enrollment token":        enroll.ReasonTokenInvalid,
	} {
		_, err := authEnrollTokens{client: enrollClient{err: status.Error(codes.Unauthenticated, msg)}}.VerifyEnrollment(ctx, "tok")
		var re *enroll.RefusalError
		if !errors.As(err, &re) || re.Reason != want {
			t.Fatalf("%q: %v", msg, err)
		}
	}
	for _, e := range []error{status.Error(codes.Unavailable, "enrollment token cannot be used"), status.Error(codes.PermissionDenied, "x"), errors.New("dial")} {
		_, err := authEnrollTokens{client: enrollClient{err: e}}.VerifyEnrollment(ctx, "tok")
		if !errors.Is(err, enroll.ErrVerifierUnavailable) {
			t.Fatalf("%v: %v", e, err)
		}
	}
	g, err := authEnrollTokens{client: enrollClient{resp: &authv1.VerifyEnrollmentTokenResponse{TenantId: "t1", SpiffePaths: []string{"spiffe://example.org/a"}}}}.VerifyEnrollment(ctx, "tok")
	if err != nil || g.TenantID != "t1" || g.SpiffePaths[0] != "spiffe://example.org/a" {
		t.Fatalf("grant: %+v %v", g, err)
	}
}
