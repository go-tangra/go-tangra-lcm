package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

var clk = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// fakeVerifier is a single-use enrollment-token verifier double: it returns a
// fixed grant, erroring on the second call when singleUse is set (modelling
// replay) or always when err is set (invalid/expired).
type fakeVerifier struct {
	grant     EnrollGrant
	err       error
	singleUse bool
	calls     int
}

func (f *fakeVerifier) VerifyEnrollment(_ context.Context, _ string) (EnrollGrant, error) {
	f.calls++
	if f.err != nil {
		return EnrollGrant{}, f.err
	}
	if f.singleUse && f.calls > 1 {
		return EnrollGrant{}, errors.New("token already used")
	}
	return f.grant, nil
}

type fixture struct {
	mem   *memstore.Mem
	iss   *issue.Service
	az    *authz.Authorizer
	aw    *audit.Writer
	tok   *fakeVerifier
	svc   *Service
	admin authz.Subjects
}

func newFixture(t *testing.T, cfg Config, tok *fakeVerifier) *fixture {
	t.Helper()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	mem := memstore.New()
	mem.Now = func() time.Time { return clk }
	auth := ca.New(mem, env)
	auth.Clock = func() time.Time { return clk }
	az := authz.New(mem)
	az.SetClock(func() time.Time { return clk })
	aw := audit.NewWriter(mem, nil)
	t.Cleanup(aw.Close)
	iss := issue.New(mem, auth, env, az, aw, func() time.Time { return clk })
	svc := New(mem, iss, az, aw, tok, cfg, func() time.Time { return clk })
	return &fixture{
		mem: mem, iss: iss, az: az, aw: aw, tok: tok, svc: svc,
		admin: authz.Subjects{TenantID: "t1", UserID: "u-admin", Roles: []string{"admin"}},
	}
}

func (f *fixture) audits(t *testing.T) map[string]string {
	t.Helper()
	f.aw.Flush(context.Background())
	out := map[string]string{}
	for _, r := range f.mem.Audit {
		out[r.EventType] = r.Outcome
	}
	return out
}

func (f *fixture) mustIssuer(t *testing.T) {
	t.Helper()
	if _, err := f.iss.CreateIssuer(context.Background(), f.admin, issue.IssuerInput{
		Name: "primary", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
}

func makeCSR(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestEnrollAutoApproveReturnsBundle(t *testing.T) {
	f := newFixture(t, Config{AutoApprove: true}, nil)
	f.mustIssuer(t)

	res, err := f.svc.Enroll(context.Background(), f.admin, EnrollInput{SpiffeID: "spiffe://example.org/wl"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Status != "issued" || res.Bundle == nil {
		t.Fatalf("expected inline bundle, got %+v", res)
	}
	if res.Bundle.KeyPEM == "" {
		t.Fatalf("expected a delivered key for a generated keypair")
	}
	if res.Bundle.Certificate.SpiffeID != "spiffe://example.org/wl" {
		t.Fatalf("spiffe id = %s", res.Bundle.Certificate.SpiffeID)
	}
	if a := f.audits(t); a[string(audit.EnrollmentIssued)] != audit.OutcomeOK {
		t.Fatalf("missing enrollment_issued audit: %v", a)
	}
}

func TestEnrollManualReturnsPendingRequest(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)

	res, err := f.svc.Enroll(context.Background(), f.admin, EnrollInput{SpiffeID: "spiffe://example.org/wl", CSRPEM: makeCSR(t)})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Status != "pending" || res.RequestID == "" || res.Bundle != nil {
		t.Fatalf("expected a pending request, got %+v", res)
	}
	r, err := f.svc.GetRequest(context.Background(), f.admin, res.RequestID)
	if err != nil {
		t.Fatalf("GetRequest: %v", err)
	}
	if r.Status != "pending" || !r.HasCSR {
		t.Fatalf("stored request = %+v", r)
	}
	if a := f.audits(t); a[string(audit.CertificateRequested)] != audit.OutcomeOK {
		t.Fatalf("missing certificate_requested audit: %v", a)
	}
}

func TestEnrollTokenValidSucceeds(t *testing.T) {
	tok := &fakeVerifier{grant: EnrollGrant{TenantID: "t1", SpiffePaths: []string{"spiffe://example.org/agent"}}, singleUse: true}
	f := newFixture(t, Config{AutoApprove: true}, tok)
	f.mustIssuer(t)

	// A caller with no platform entitlement, relying solely on the token.
	caller := authz.Subjects{TenantID: "t1"}
	res, err := f.svc.Enroll(context.Background(), caller, EnrollInput{
		SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "tok-1",
	})
	if err != nil {
		t.Fatalf("Enroll with token: %v", err)
	}
	if res.Bundle == nil || res.Bundle.Certificate.SpiffeID != "spiffe://example.org/agent" {
		t.Fatalf("token enrollment did not issue the granted identity: %+v", res)
	}
}

func TestEnrollTokenWrongIdentityForbidden(t *testing.T) {
	tok := &fakeVerifier{grant: EnrollGrant{TenantID: "t1", SpiffePaths: []string{"spiffe://example.org/agent"}}}
	f := newFixture(t, Config{AutoApprove: true}, tok)
	f.mustIssuer(t)

	caller := authz.Subjects{TenantID: "t1"}
	_, err := f.svc.Enroll(context.Background(), caller, EnrollInput{
		SpiffeID: "spiffe://example.org/impostor", EnrollmentToken: "tok-1",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if a := f.audits(t); a[string(audit.EnrollmentRefused)] != audit.OutcomeRefused {
		t.Fatalf("missing enrollment_refused audit: %v", a)
	}
	// Nothing was issued.
	if len(f.mem.Certificates) != 0 {
		t.Fatalf("a certificate was issued despite refusal")
	}
}

func TestEnrollTokenReplayRefused(t *testing.T) {
	tok := &fakeVerifier{grant: EnrollGrant{TenantID: "t1", SpiffePaths: []string{"spiffe://example.org/agent"}}, singleUse: true}
	f := newFixture(t, Config{AutoApprove: true}, tok)
	f.mustIssuer(t)
	caller := authz.Subjects{TenantID: "t1"}

	if _, err := f.svc.Enroll(context.Background(), caller, EnrollInput{SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "tok-1"}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Second use of the same token is rejected by the verifier -> forbidden.
	_, err := f.svc.Enroll(context.Background(), caller, EnrollInput{SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "tok-1"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("replayed token want ErrForbidden, got %v", err)
	}
}

func TestApproveEnqueuesJobAndWorkerIssues(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()

	res, err := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/db"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	rv, err := f.svc.ApproveRequest(ctx, f.admin, res.RequestID, "looks good")
	if err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	if rv.Status != "approved" {
		t.Fatalf("status = %s", rv.Status)
	}
	jobs, _, err := f.svc.ListJobs(ctx, f.admin, JobFilter{})
	if err != nil || len(jobs) != 1 || jobs[0].Status != "queued" {
		t.Fatalf("expected one queued job, got %v (%v)", jobs, err)
	}

	sched := NewScheduler(f.svc, SchedulerConfig{}, nil, nil)
	sched.SetClock(func() time.Time { return clk })
	n, err := sched.Once(ctx)
	if err != nil || n != 1 {
		t.Fatalf("worker Once = %d, %v", n, err)
	}
	job, err := f.svc.GetJob(ctx, f.admin, jobs[0].ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Status != "completed" || job.ResultCertificateID == "" {
		t.Fatalf("job not completed: %+v", job)
	}
	if _, ok := f.mem.Certificates[job.ResultCertificateID]; !ok {
		t.Fatalf("issued certificate %q not stored", job.ResultCertificateID)
	}
	done, err := f.svc.GetRequest(ctx, f.admin, res.RequestID)
	if err != nil || done.Status != "issued" {
		t.Fatalf("request not marked issued: %+v (%v)", done, err)
	}
	if a := f.audits(t); a[string(audit.EnrollmentIssued)] != audit.OutcomeOK {
		t.Fatalf("missing enrollment_issued audit: %v", a)
	}
}

func TestRejectSetsRejected(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()

	res, _ := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/no"})
	rv, err := f.svc.RejectRequest(ctx, f.admin, res.RequestID, "denied")
	if err != nil {
		t.Fatalf("RejectRequest: %v", err)
	}
	if rv.Status != "rejected" || rv.Reason != "denied" {
		t.Fatalf("reject result = %+v", rv)
	}
	jobs, _, _ := f.svc.ListJobs(ctx, f.admin, JobFilter{})
	if len(jobs) != 0 {
		t.Fatalf("reject must not enqueue a job")
	}
	if a := f.audits(t); a[string(audit.RequestRejected)] != audit.OutcomeOK {
		t.Fatalf("missing request_rejected audit: %v", a)
	}
}

func TestApproveStateMachineConflict(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()

	res, _ := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/x"})
	if _, err := f.svc.ApproveRequest(ctx, f.admin, res.RequestID, ""); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	_, err := f.svc.ApproveRequest(ctx, f.admin, res.RequestID, "")
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConflictError, got %v", err)
	}
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("ConflictError must unwrap to store.ErrConflict")
	}
	// Reject of a non-pending request also conflicts.
	if _, err := f.svc.RejectRequest(ctx, f.admin, res.RequestID, ""); !errors.As(err, &ce) {
		t.Fatalf("reject of approved want ConflictError, got %v", err)
	}
}

func TestApproveForbiddenForStranger(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()

	res, _ := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/x"})
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-stranger"}
	if _, err := f.svc.ApproveRequest(ctx, stranger, res.RequestID, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("stranger approve want ErrForbidden, got %v", err)
	}
}

func TestJobCancel(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()

	res, _ := f.svc.Enroll(ctx, f.admin, EnrollInput{SpiffeID: "spiffe://example.org/c"})
	if _, err := f.svc.ApproveRequest(ctx, f.admin, res.RequestID, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	jobs, _, _ := f.svc.ListJobs(ctx, f.admin, JobFilter{})
	got, err := f.svc.CancelJob(ctx, f.admin, jobs[0].ID)
	if err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if got.Status != "failed" || got.Error != "cancelled" {
		t.Fatalf("cancel result = %+v", got)
	}
	// Cancelling again (already failed) conflicts.
	if _, err := f.svc.CancelJob(ctx, f.admin, jobs[0].ID); err == nil {
		t.Fatalf("cancel of failed job should conflict")
	}
}

// failingRequest pins a valid issuer but requests a cross-trust-domain SPIFFE
// id, so issuance fails at the worker (a controlled failure).
func (f *fixture) failingRequest(t *testing.T, ctx context.Context) string {
	t.Helper()
	iss, err := f.mem.DefaultIssuer(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("DefaultIssuer: %v", err)
	}
	rv, err := f.svc.CreateRequest(ctx, f.admin, RequestInput{IssuerID: iss.ID, SpiffeID: "spiffe://other.org/x"})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := f.svc.ApproveRequest(ctx, f.admin, rv.ID, ""); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}
	return rv.ID
}

func TestJobRetryAfterFailure(t *testing.T) {
	f := newFixture(t, Config{MaxAttempts: 3}, nil)
	f.mustIssuer(t)
	ctx := context.Background()
	f.failingRequest(t, ctx)

	sched := NewScheduler(f.svc, SchedulerConfig{}, nil, nil)
	sched.SetClock(func() time.Time { return clk })
	if _, err := sched.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	jobs, _, _ := f.svc.ListJobs(ctx, f.admin, JobFilter{})
	if jobs[0].Status != "failed" || jobs[0].Attempts != 1 || jobs[0].Error == "" {
		t.Fatalf("expected a failed job with one attempt and a scrubbed error, got %+v", jobs[0])
	}
	// Attempts remain: retry requeues.
	got, err := f.svc.RetryJob(ctx, f.admin, jobs[0].ID)
	if err != nil {
		t.Fatalf("RetryJob: %v", err)
	}
	if got.Status != "queued" || got.Error != "" {
		t.Fatalf("retry result = %+v", got)
	}
}

func TestJobRetryMaxAttempts(t *testing.T) {
	f := newFixture(t, Config{MaxAttempts: 1}, nil)
	f.mustIssuer(t)
	ctx := context.Background()
	f.failingRequest(t, ctx)

	sched := NewScheduler(f.svc, SchedulerConfig{}, nil, nil)
	sched.SetClock(func() time.Time { return clk })
	if _, err := sched.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	jobs, _, _ := f.svc.ListJobs(ctx, f.admin, JobFilter{})
	if jobs[0].Status != "failed" || jobs[0].Attempts != 1 {
		t.Fatalf("expected failed after one attempt, got %+v", jobs[0])
	}
	// Attempts exhausted (1 of 1): retry conflicts.
	_, err := f.svc.RetryJob(ctx, f.admin, jobs[0].ID)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConflictError for exhausted attempts, got %v", err)
	}
}

func TestEnrollInvalidSpiffeID(t *testing.T) {
	f := newFixture(t, Config{AutoApprove: true}, nil)
	f.mustIssuer(t)
	_, err := f.svc.Enroll(context.Background(), f.admin, EnrollInput{SpiffeID: "not-a-spiffe-id"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "spiffe_id" {
		t.Fatalf("want spiffe_id ValidationError, got %v", err)
	}
}

func TestEnrollTokenInvalidRefused(t *testing.T) {
	tok := &fakeVerifier{err: errors.New("expired")}
	f := newFixture(t, Config{AutoApprove: true}, tok)
	f.mustIssuer(t)
	_, err := f.svc.Enroll(context.Background(), authz.Subjects{TenantID: "t1"}, EnrollInput{
		SpiffeID: "spiffe://example.org/agent", EnrollmentToken: "bad",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("invalid token want ErrForbidden, got %v", err)
	}
}

func TestListRequestsAndRequesterScope(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ctx := context.Background()
	user := authz.Subjects{TenantID: "t1", UserID: "u-req"}

	rv, err := f.svc.CreateRequest(ctx, user, RequestInput{SpiffeID: "spiffe://example.org/own"})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	// The requester reads and lists their own request.
	if _, err := f.svc.GetRequest(ctx, user, rv.ID); err != nil {
		t.Fatalf("requester GetRequest: %v", err)
	}
	list, _, err := f.svc.ListRequests(ctx, user, RequestFilter{Status: "pending"})
	if err != nil || len(list) != 1 || list[0].ID != rv.ID {
		t.Fatalf("requester list = %v (%v)", list, err)
	}
	// An admin lists it too.
	adminList, _, err := f.svc.ListRequests(ctx, f.admin, RequestFilter{})
	if err != nil || len(adminList) != 1 {
		t.Fatalf("admin list = %v (%v)", adminList, err)
	}
	// A stranger (no grant, not the requester) cannot read it.
	stranger := authz.Subjects{TenantID: "t1", UserID: "u-other"}
	if _, err := f.svc.GetRequest(ctx, stranger, rv.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("stranger GetRequest want forbidden, got %v", err)
	}
	sList, _, _ := f.svc.ListRequests(ctx, stranger, RequestFilter{})
	if len(sList) != 0 {
		t.Fatalf("stranger should see no requests, got %d", len(sList))
	}
}

func TestSchedulerRunStops(t *testing.T) {
	f := newFixture(t, Config{}, nil)
	f.mustIssuer(t)
	ticks := make(chan struct{}, 4)
	sched := NewScheduler(f.svc, SchedulerConfig{Interval: time.Millisecond}, nil, func() { ticks <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sched.Run(ctx); close(done) }()
	<-ticks // at least one loop ran
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := encodeCursor(clk, "id-1")
	ts, id, err := decodeCursor(c)
	if err != nil || id != "id-1" || !ts.Equal(clk) {
		t.Fatalf("round trip = %v %q %v", ts, id, err)
	}
	if _, _, err := decodeCursor("garbage-no-pipe"); err == nil {
		t.Fatal("expected a bad-cursor error")
	}
}

func TestNewDefaultsClockAndAttempts(t *testing.T) {
	s := New(nil, nil, nil, nil, nil, Config{}, nil)
	if s.now == nil {
		t.Fatal("clock not defaulted")
	}
	if s.cfg.MaxAttempts != 5 {
		t.Fatalf("MaxAttempts default = %d, want 5", s.cfg.MaxAttempts)
	}
}
