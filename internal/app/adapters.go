package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
)

// hubPublisher fans a certificate lifecycle event out to every signed-in user
// of the tenant (SSE + gRPC Agent) and, when set, to the tenant's outbound
// webhooks. Publishing is best-effort and goroutine-safe.
type hubPublisher struct {
	hub *stream.Hub
	wh  *webhook.Service
}

// hookEvent maps a stream lifecycle type to the webhook event name.
var hookEvent = map[string]string{
	"issued":  webhook.EventIssued,
	"renewed": webhook.EventRenewed,
	"revoked": webhook.EventRevoked,
	"failed":  webhook.EventFailed,
}

func (p hubPublisher) Publish(ctx context.Context, tenantID, eventType, certificateID, spiffeID string, notAfter time.Time) {
	payload := map[string]any{"certificate_id": certificateID, "spiffe_id": spiffeID}
	if !notAfter.IsZero() {
		payload["not_after"] = notAfter.UTC().Format(time.RFC3339)
	}
	if p.hub != nil {
		// Publish to the shared platform bus with a namespaced type so the
		// gateway SSE hub can fan it to browsers unambiguously.
		_, _ = p.hub.PublishID(ctx, tenantID, nil, true, "certificate."+eventType, payload, false)
	}
	if p.wh != nil {
		if evt, ok := hookEvent[eventType]; ok {
			body, _ := json.Marshal(map[string]any{"event": evt, "tenant": tenantID, "data": payload})
			// Deliver out-of-band so a slow endpoint never blocks the request.
			go func() {
				dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				_ = p.wh.Deliver(dctx, tenantID, evt, body)
			}()
		}
	}
}

// PublishFailed fans a certificate.failed event to every user of the tenant
// (async issuance failure) and fires the "failed" webhook. detail carries the
// domains and a client-safe error message.
func (p hubPublisher) PublishFailed(ctx context.Context, tenantID string, detail map[string]any) {
	if p.hub != nil {
		_, _ = p.hub.PublishID(ctx, tenantID, nil, true, "certificate.failed", detail, false)
	}
	if p.wh != nil {
		body, _ := json.Marshal(map[string]any{"event": webhook.EventFailed, "tenant": tenantID, "data": detail})
		go func() {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = p.wh.Deliver(dctx, tenantID, webhook.EventFailed, body)
		}()
	}
}

// sysRenewer adapts issue.Service to the renewal scheduler's Renewer using the
// privileged system renewal path (no user grant required).
type sysRenewer struct{ svc *issue.Service }

func (r sysRenewer) Renew(ctx context.Context, subj authz.Subjects, certID string) (issue.Bundle, error) {
	return r.svc.RenewSystem(ctx, subj.TenantID, certID)
}

// stubEnrollTokens rejects every enrollment token until the auth service mints
// them (contracts/auth-changes.md). Platform-identity enrollment is unaffected.
type stubEnrollTokens struct{}

func (stubEnrollTokens) VerifyEnrollment(context.Context, string) (enroll.EnrollGrant, error) {
	return enroll.EnrollGrant{}, authz.ErrForbidden
}

// authEnrollTokens verifies enrollment (join) tokens against the auth service,
// which mints them as single-use EdDSA JWTs and burns the jti on verify. The
// grant it returns names the SPIFFE ids the token authorises.
type authEnrollTokens struct{ client authv1.EnrollmentClient }

func (a authEnrollTokens) VerifyEnrollment(ctx context.Context, token string) (enroll.EnrollGrant, error) {
	resp, err := a.client.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: token})
	if err != nil {
		return enroll.EnrollGrant{}, verifyError(err)
	}
	return enroll.EnrollGrant{TenantID: resp.GetTenantId(), SpiffePaths: resp.GetSpiffePaths()}, nil
}

// authTokenReasons are the closed reasons auth puts in the status message of a
// codes.Unauthenticated VerifyEnrollmentToken refusal. Matching the message
// (not a new proto field) works with the released auth SDK.
var authTokenReasons = map[string]string{
	"enrollment_token_expired":       enroll.ReasonTokenExpired,
	"enrollment_token_not_yet_valid": enroll.ReasonTokenNotYetValid,
	"enrollment_token_used":          enroll.ReasonTokenUsed,
	"enrollment_token_invalid":       enroll.ReasonTokenInvalid,
	// Older auth releases: the replay refusal had its own fixed message.
	"enrollment token cannot be used": enroll.ReasonTokenUsed,
}

// verifyError turns an auth verify failure into an enroll refusal: an
// Unauthenticated verdict carries its reason (unknown text, e.g. an older auth,
// stays enrollment_token_invalid); anything else is no verdict on the token and
// is retryable (auth unreachable, jti burn failed, lcm not permitted).
func verifyError(err error) error {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		return fmt.Errorf("%w: %w", enroll.ErrVerifierUnavailable, err)
	}
	reason, known := authTokenReasons[st.Message()]
	if !known {
		reason = enroll.ReasonTokenInvalid
	}
	return &enroll.RefusalError{Reason: reason}
}
