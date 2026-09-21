package renew

import (
	"bytes"
	"context"
	"errors"
	"sync"
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

var base = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// testCfg is the standard scheduler config: 30-day long window, renew at half.
func testCfg() Config {
	return Config{Interval: time.Second, Workers: 4, ShortLivedFraction: 0.5, LongLivedWindow: 30 * day}
}

// ---- fakes

type pubEvent struct {
	tenantID, eventType, certID, spiffeID string
	notAfter                              time.Time
}

type fakePub struct {
	mu     sync.Mutex
	events []pubEvent
}

func (p *fakePub) Publish(_ context.Context, tenantID, eventType, certID, spiffeID string, notAfter time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, pubEvent{tenantID, eventType, certID, spiffeID, notAfter})
}

func (p *fakePub) snapshot() []pubEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pubEvent(nil), p.events...)
}

// fakeRenewer records renewal calls, may fail selected certificates, and (when
// given a store) supersedes the renewed row so the next scan skips it.
type fakeRenewer struct {
	mu     sync.Mutex
	calls  []string
	failOn map[string]error
	mem    *memstore.Mem
}

func (r *fakeRenewer) Renew(ctx context.Context, subj authz.Subjects, certID string) (issue.Bundle, error) {
	r.mu.Lock()
	r.calls = append(r.calls, certID)
	err := r.failOn[certID]
	r.mu.Unlock()
	if err != nil {
		return issue.Bundle{}, err
	}
	newID := store.NewID()
	spiffe := "spiffe://example.org/svc"
	notAfter := base.Add(365 * day)
	if r.mem != nil {
		old, gerr := r.mem.GetCertificate(ctx, subj.TenantID, certID)
		if gerr != nil {
			return issue.Bundle{}, gerr
		}
		spiffe = old.SpiffeID
		if serr := r.mem.SetCertificateStatus(ctx, subj.TenantID, certID, old.Status, &newID); serr != nil {
			return issue.Bundle{}, serr
		}
	}
	return issue.Bundle{Certificate: issue.CertificateView{ID: newID, SpiffeID: spiffe, NotAfter: notAfter}}, nil
}

func (r *fakeRenewer) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// ---- Due boundaries

func TestDueBoundaries(t *testing.T) {
	s := NewScheduler(nil, nil, nil, testCfg(), nil, nil, nil)

	// Long-lived cert: TTL 90d, window = max(30d, 0.5*90d) = 45d.
	longCert := store.IssuedCertificate{NotBefore: base, NotAfter: base.Add(90 * day)}
	if s.Due(longCert, base) {
		t.Fatal("long-lived cert far from expiry must not be due")
	}
	if s.Due(longCert, base.Add(44*day)) {
		t.Fatal("long-lived cert 46d before expiry must not be due yet")
	}
	renewAt := longCert.NotAfter.Add(-45 * day)
	if !s.Due(longCert, renewAt) {
		t.Fatal("long-lived cert at renewAt (notAfter-45d) must be due")
	}
	if !s.Due(longCert, base.Add(80*day)) {
		t.Fatal("long-lived cert well inside the window must be due")
	}

	// Short-lived SVID: TTL 1h, window = 0.5h.
	svid := store.IssuedCertificate{NotBefore: base, NotAfter: base.Add(time.Hour)}
	if s.Due(svid, base) {
		t.Fatal("short SVID at issuance must not be due")
	}
	if s.Due(svid, base.Add(29*time.Minute)) {
		t.Fatal("short SVID with >30m remaining must not be due")
	}
	if !s.Due(svid, base.Add(30*time.Minute)) {
		t.Fatal("short SVID at half TTL remaining must be due")
	}
	if !s.Due(svid, base.Add(55*time.Minute)) {
		t.Fatal("short SVID past the fraction must be due")
	}
}

// ---- real issuance service: renews, publishes, and does not re-renew (SC-003)

type realFixture struct {
	mem *memstore.Mem
	svc *issue.Service
	now func() time.Time
	set func(time.Time)
}

func newRealFixture(t *testing.T) *realFixture {
	t.Helper()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	cur := base
	clock := func() time.Time { return cur }
	mem := memstore.New()
	mem.Now = clock
	auth := ca.New(mem, env)
	auth.Clock = clock
	az := authz.New(mem)
	az.SetClock(clock)
	aw := audit.NewWriter(mem, nil)
	t.Cleanup(aw.Close)
	svc := issue.New(mem, auth, env, az, aw, clock)
	return &realFixture{mem: mem, svc: svc, now: clock, set: func(tm time.Time) { cur = tm }}
}

func TestRunOnceRenewsPublishesAndIsIdempotent(t *testing.T) {
	f := newRealFixture(t)
	ctx := context.Background()
	admin := authz.Subjects{TenantID: "t1", UserID: "u-admin", Roles: []string{"admin"}}

	iv, err := f.svc.CreateIssuer(ctx, admin, issue.IssuerInput{
		Name: "primary", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}

	// Three short-lived SVIDs (TTL 1h) issued at base.
	ids := make([]string, 0, 3)
	for _, name := range []string{"a", "b", "c"} {
		b, ierr := f.svc.Issue(ctx, admin, issue.IssueInput{
			IssuerID: iv.ID, SpiffeID: "spiffe://example.org/" + name, ValiditySeconds: 3600, DeliverKey: true,
		})
		if ierr != nil {
			t.Fatalf("Issue %s: %v", name, ierr)
		}
		ids = append(ids, b.Certificate.ID)
		// Tenant-wide grant so the system scope may renew (service subjects hold
		// only tenant-wide grants).
		if _, gerr := f.mem.UpsertGrant(ctx, store.Grant{
			ID: store.NewID(), TenantID: "t1", ResourceType: authz.Certificate, ResourceID: b.Certificate.ID,
			SubjectType: authz.SubjectTenant, Relation: authz.Owner,
		}); gerr != nil {
			t.Fatalf("grant: %v", gerr)
		}
	}

	pub := &fakePub{}
	s := NewScheduler(f.mem, f.svc, pub, testCfg(), nil, f.now, nil)

	// Not yet due at issuance.
	if n, rerr := s.RunOnce(ctx); rerr != nil || n != 0 {
		t.Fatalf("RunOnce at issuance = (%d, %v); want (0, nil)", n, rerr)
	}

	// Advance to 50 minutes in: 10m remaining < 30m window => all due.
	f.set(base.Add(50 * time.Minute))

	n, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("renewed = %d; want 3", n)
	}
	evs := pub.snapshot()
	if len(evs) != 3 {
		t.Fatalf("published %d events; want 3", len(evs))
	}
	for _, e := range evs {
		if e.eventType != "renewed" {
			t.Fatalf("event type = %q; want renewed", e.eventType)
		}
		if e.tenantID != "t1" || e.certID == "" || e.spiffeID == "" {
			t.Fatalf("event missing fields: %+v", e)
		}
	}
	// Every original certificate is superseded.
	for _, id := range ids {
		old, gerr := f.mem.GetCertificate(ctx, "t1", id)
		if gerr != nil {
			t.Fatalf("get %s: %v", id, gerr)
		}
		if old.SupersededBy == nil {
			t.Fatalf("certificate %s not superseded", id)
		}
	}

	// SC-003: a second immediate pass renews nothing and publishes nothing new.
	n2, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second RunOnce renewed = %d; want 0 (no duplicate)", n2)
	}
	if got := len(pub.snapshot()); got != 3 {
		t.Fatalf("events after second pass = %d; want 3", got)
	}
}

// ---- scan errors surface

func TestRunOnceScanError(t *testing.T) {
	mem := memstore.New()
	mem.Now = func() time.Time { return base }
	mem.FailOn("DueForRenewal", errors.New("db down"))
	s := NewScheduler(mem, &fakeRenewer{}, &fakePub{}, testCfg(), nil, func() time.Time { return base }, nil)
	if n, err := s.RunOnce(context.Background()); err == nil || n != 0 {
		t.Fatalf("RunOnce = (%d, %v); want (0, error)", n, err)
	}
}

// ---- Run ticks, renews, heartbeats, and honors cancellation

func TestRunTicksAndCancels(t *testing.T) {
	mem := memstore.New()
	mem.Now = func() time.Time { return base }
	ctx := context.Background()
	if err := mem.InsertIssuer(ctx, store.Issuer{ID: "iss1", TenantID: "t1", TrustDomain: "example.org", Type: "self_signed", Enabled: true}); err != nil {
		t.Fatalf("InsertIssuer: %v", err)
	}
	if err := mem.InsertCertificate(ctx, store.IssuedCertificate{
		ID: "c1", TenantID: "t1", IssuerID: "iss1", Serial: "c1", SpiffeID: "spiffe://example.org/c1",
		NotBefore: base.Add(-50 * time.Minute), NotAfter: base.Add(10 * time.Minute), Status: "active",
	}); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	var ticks int
	done := make(chan struct{})
	r := &fakeRenewer{mem: mem}
	cfg := testCfg()
	cfg.Interval = time.Millisecond
	// The heartbeat cancels after the first pass so Run returns deterministically.
	s := NewScheduler(mem, r, &fakePub{}, cfg, nil, func() time.Time { return base }, func() {
		ticks++
		cancel()
	})
	go func() { s.Run(runCtx); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Run did not return after cancellation")
	}
	if ticks < 1 {
		t.Fatalf("heartbeat not called; ticks=%d", ticks)
	}
	if got := len(r.recorded()); got != 1 {
		t.Fatalf("renewed %d in Run; want 1", got)
	}
}

// ---- constructor defaults apply when fields are zero/out of range

func TestNewSchedulerDefaults(t *testing.T) {
	s := NewScheduler(nil, nil, nil, Config{}, nil, nil, nil)
	if s.cfg.Interval <= 0 || s.cfg.Workers < 1 || s.cfg.LongLivedWindow <= 0 {
		t.Fatalf("defaults not applied: %+v", s.cfg)
	}
	if s.cfg.ShortLivedFraction <= 0 || s.cfg.ShortLivedFraction >= 1 {
		t.Fatalf("fraction default not applied: %v", s.cfg.ShortLivedFraction)
	}
	if s.clock == nil || s.tick == nil || s.log == nil {
		t.Fatal("nil clock/tick/log not defaulted")
	}
	// Defaults yield a sensible window (30d long window, 0.5 fraction).
	c := store.IssuedCertificate{NotBefore: base, NotAfter: base.Add(90 * day)}
	if s.Due(c, base) || !s.Due(c, base.Add(80*day)) {
		t.Fatal("Due with defaulted config behaves unexpectedly")
	}
}

// ---- per-certificate errors do not abort the batch

func TestRunOnceErrorDoesNotAbortBatch(t *testing.T) {
	mem := memstore.New()
	mem.Now = func() time.Time { return base }
	ctx := context.Background()

	// A minimal issuer so InsertCertificate accepts the rows.
	if err := mem.InsertIssuer(ctx, store.Issuer{ID: "iss1", TenantID: "t1", TrustDomain: "example.org", Type: "self_signed", Enabled: true}); err != nil {
		t.Fatalf("InsertIssuer: %v", err)
	}

	// Three due short-lived certs (TTL 1h, 50m elapsed => due).
	ids := []string{"cert-a", "cert-b", "cert-c"}
	for _, id := range ids {
		if err := mem.InsertCertificate(ctx, store.IssuedCertificate{
			ID: id, TenantID: "t1", IssuerID: "iss1", Serial: id, SpiffeID: "spiffe://example.org/" + id,
			NotBefore: base.Add(-50 * time.Minute), NotAfter: base.Add(10 * time.Minute), Status: "active",
		}); err != nil {
			t.Fatalf("InsertCertificate %s: %v", id, err)
		}
	}

	r := &fakeRenewer{failOn: map[string]error{"cert-b": errors.New("mint failed")}, mem: mem}
	pub := &fakePub{}
	s := NewScheduler(mem, r, pub, testCfg(), nil, func() time.Time { return base }, nil)

	n, err := s.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Fatalf("renewed = %d; want 2 (one failed)", n)
	}
	if got := len(r.recorded()); got != 3 {
		t.Fatalf("Renew attempted %d times; want 3 (all attempted)", got)
	}
	evs := pub.snapshot()
	if len(evs) != 2 {
		t.Fatalf("published %d events; want 2 (only successes)", len(evs))
	}
	for _, e := range evs {
		if e.certID == "" {
			t.Fatalf("published event for failed cert: %+v", e)
		}
	}
	// The failed certificate is still a candidate on the next scan; the two
	// successes were superseded by the fake and are skipped.
	f, gerr := mem.GetCertificate(ctx, "t1", "cert-b")
	if gerr != nil {
		t.Fatalf("get cert-b: %v", gerr)
	}
	if f.SupersededBy != nil {
		t.Fatal("failed certificate must not be superseded")
	}
}
