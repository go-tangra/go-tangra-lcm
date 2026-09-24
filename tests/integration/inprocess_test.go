// Package integration holds the lcm end-to-end tests. This file is the
// in-process variant (no testcontainers, no build tag): it wires the real
// services over the in-memory store and the in-process stream Hub to prove the
// US3 SVID-lifecycle flow — enroll, auto-renew and live distribution — without
// external infrastructure. The tagged testcontainers suite covers the same
// flows against real TimescaleDB/Valkey.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/renew"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
)

const tenant = "11111111-1111-7111-8111-111111111111"

func admin() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

type hubPub struct{ hub *stream.Hub }

func (p hubPub) Publish(ctx context.Context, tenantID, eventType, certID, spiffeID string, notAfter time.Time) {
	_, _ = p.hub.PublishID(ctx, tenantID, nil, true, eventType, map[string]any{"certificate_id": certID, "spiffe_id": spiffeID}, false)
}

// TestUS3_EnrollAutoRenewLiveStream: enroll (auto-approve) yields an SVID; when
// it nears expiry the renewal scheduler renews it and a "renewed" event reaches
// an open live stream (SC-003 no-duplicate + SC-004 live delivery), in-process.
func TestUS3_EnrollAutoRenewLiveStream(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	az := authz.New(st)
	aw := audit.NewWriter(st, nil)
	defer aw.Close()
	clock := time.Unix(1700000000, 0)
	iss := issue.New(st, ca.New(st, env), env, az, aw, func() time.Time { return clock })

	// An issuer with a short TTL ceiling so the cert is due for renewal soon.
	if _, err := iss.CreateIssuer(ctx, admin(), issue.IssuerInput{Name: "root", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true}); err != nil {
		t.Fatalf("issuer: %v", err)
	}

	// Enroll (auto-approve) via the platform identity.
	en := enroll.New(st, iss, az, aw, rejectTokens{}, enroll.Config{AutoApprove: true}, func() time.Time { return clock })
	res, err := en.Enroll(ctx, admin(), enroll.EnrollInput{SpiffeID: "spiffe://example.org/svc/api"})
	if err != nil || res.Status != "issued" || res.Bundle == nil {
		t.Fatalf("enroll: %v status=%s", err, res.Status)
	}
	certID := res.Bundle.Certificate.ID

	// Open a live stream and advance the clock to just before expiry.
	hub := stream.NewHub(stream.NewMemory(), stream.Config{}, nil)
	defer hub.Close()
	sub, err := hub.Subscribe(ctx, tenant, admin().UserID, "")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Close()

	sched := renew.NewScheduler(st, sysRenew{iss}, hubPub{hub}, renew.Config{Interval: time.Second, Workers: 2, ShortLivedFraction: 0.5, LongLivedWindow: 30 * 24 * time.Hour}, nil, func() time.Time { return clock }, nil)

	clock = clock.Add(80 * 24 * time.Hour) // within the default 90d TTL's renewal window
	n, err := sched.RunOnce(ctx)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 renewal, got %d", n)
	}
	// A second pass renews nothing (SC-003 idempotency).
	if n2, _ := sched.RunOnce(ctx); n2 != 0 {
		t.Fatalf("second pass renewed %d, want 0", n2)
	}
	// The renewed event reached the open stream (SC-004).
	select {
	case ev := <-sub.Events():
		if ev.Type != "renewed" {
			t.Fatalf("event type = %q, want renewed", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no renewed event within 2s")
	}
	_ = certID
}

// TestUS3_ManualApproveIssues: with auto-approve off, enroll yields a pending
// request; approving it enqueues a job the worker processes into a real cert.
func TestUS3_ManualApproveIssues(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	env, _ := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	az := authz.New(st)
	aw := audit.NewWriter(st, nil)
	defer aw.Close()
	clock := time.Unix(1700000000, 0)
	iss := issue.New(st, ca.New(st, env), env, az, aw, func() time.Time { return clock })
	if _, err := iss.CreateIssuer(ctx, admin(), issue.IssuerInput{Name: "root", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	en := enroll.New(st, iss, az, aw, rejectTokens{}, enroll.Config{AutoApprove: false}, func() time.Time { return clock })
	res, err := en.Enroll(ctx, admin(), enroll.EnrollInput{SpiffeID: "spiffe://example.org/svc/worker"})
	if err != nil || res.Status != "pending" || res.RequestID == "" {
		t.Fatalf("manual enroll: %v status=%s", err, res.Status)
	}
	if _, err := en.ApproveRequest(ctx, admin(), res.RequestID, "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Process the enqueued job.
	worker := enroll.NewScheduler(en, enroll.SchedulerConfig{Interval: time.Second, Lease: time.Minute, Batch: 10}, nil, nil)
	if _, err := worker.Once(ctx); err != nil {
		t.Fatalf("worker: %v", err)
	}
	req, err := en.GetRequest(ctx, admin(), res.RequestID)
	if err != nil || req.Status != "issued" {
		t.Fatalf("request status = %q (err %v), want issued", req.Status, err)
	}
}

type rejectTokens struct{}

func (rejectTokens) VerifyEnrollment(context.Context, string) (enroll.EnrollGrant, error) {
	return enroll.EnrollGrant{}, authz.ErrForbidden
}

type sysRenew struct{ svc *issue.Service }

func (r sysRenew) Renew(ctx context.Context, subj authz.Subjects, certID string) (issue.Bundle, error) {
	return r.svc.RenewSystem(ctx, subj.TenantID, certID)
}
