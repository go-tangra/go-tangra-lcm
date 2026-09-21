package app

import (
	"context"
	"encoding/json"
	"time"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/stream"
	"github.com/go-freya/freya/services/lcm/internal/webhook"
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
		return enroll.EnrollGrant{}, err
	}
	return enroll.EnrollGrant{TenantID: resp.GetTenantId(), SpiffePaths: resp.GetSpiffePaths()}, nil
}
