package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Job statuses.
const (
	jobQueued     = "queued"
	jobProcessing = "processing"
	jobCompleted  = "completed"
	jobFailed     = "failed"
)

// JobView is a certificate job as returned to clients.
type JobView struct {
	ID                  string `json:"id"`
	RequestID           string `json:"request_id"`
	Type                string `json:"type"`
	Status              string `json:"status"`
	Attempts            int    `json:"attempts"`
	MaxAttempts         int    `json:"max_attempts"`
	ResultCertificateID string `json:"result_certificate_id,omitempty"`
	Error               string `json:"error,omitempty"`
	RunAfter            string `json:"run_after"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

func jobView(j store.CertificateJob) JobView {
	fmtTime := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.999999999Z07:00") }
	return JobView{
		ID: j.ID, RequestID: j.RequestID, Type: j.Type, Status: j.Status,
		Attempts: j.Attempts, MaxAttempts: j.MaxAttempts, ResultCertificateID: strp(j.ResultCertificateID),
		Error: strp(j.Error), RunAfter: fmtTime(j.RunAfter), CreatedAt: fmtTime(j.CreatedAt), UpdatedAt: fmtTime(j.UpdatedAt),
	}
}

// GetJob returns a job the caller may read (read on the request's issuer).
func (s *Service) GetJob(ctx context.Context, subj authz.Subjects, id string) (JobView, error) {
	j, err := s.st.GetJob(ctx, subj.TenantID, id)
	if err != nil {
		return JobView{}, err
	}
	if err := s.authorizeJob(ctx, subj, j, authz.Read); err != nil {
		return JobView{}, err
	}
	return jobView(j), nil
}

// JobFilter selects jobs for a listing.
type JobFilter struct {
	Status string
	Cursor string
	Limit  int
}

// ListJobs pages jobs the caller may read, newest first.
func (s *Service) ListJobs(ctx context.Context, subj authz.Subjects, f JobFilter) ([]JobView, string, error) {
	ts, id, err := decodeCursor(f.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.st.ListJobs(ctx, subj.TenantID, store.JobFilter{Status: f.Status, CursorTS: ts, CursorID: id, Limit: limit})
	if err != nil {
		return nil, "", err
	}
	out := make([]JobView, 0, len(rows))
	for _, j := range rows {
		if s.authorizeJob(ctx, subj, j, authz.Read) != nil {
			continue
		}
		out = append(out, jobView(j))
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

// CancelJob fails a queued or processing job. The caller must hold manage
// (write) on the request's issuer.
func (s *Service) CancelJob(ctx context.Context, subj authz.Subjects, id string) (JobView, error) {
	j, err := s.st.GetJob(ctx, subj.TenantID, id)
	if err != nil {
		return JobView{}, err
	}
	if err := s.authorizeJob(ctx, subj, j, authz.Write); err != nil {
		return JobView{}, err
	}
	if j.Status != jobQueued && j.Status != jobProcessing {
		return JobView{}, &ConflictError{ID: id, From: j.Status, To: jobFailed}
	}
	j.Status = jobFailed
	j.LeaseUntil = nil
	j.Error = ptrOrNil("cancelled")
	if err := s.st.UpdateJob(ctx, j); err != nil {
		return JobView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.EnrollmentRefused, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectJob, SubjectID: id, Outcome: audit.OutcomeRefused, Reason: "job cancelled",
	})
	got, err := s.st.GetJob(ctx, subj.TenantID, id)
	if err != nil {
		return JobView{}, err
	}
	return jobView(got), nil
}

// RetryJob requeues a failed job when attempts remain, else conflicts. The
// caller must hold manage (write) on the request's issuer.
func (s *Service) RetryJob(ctx context.Context, subj authz.Subjects, id string) (JobView, error) {
	j, err := s.st.GetJob(ctx, subj.TenantID, id)
	if err != nil {
		return JobView{}, err
	}
	if err := s.authorizeJob(ctx, subj, j, authz.Write); err != nil {
		return JobView{}, err
	}
	if j.Status != jobFailed {
		return JobView{}, &ConflictError{ID: id, From: j.Status, To: jobQueued}
	}
	if j.Attempts >= j.MaxAttempts {
		return JobView{}, &ConflictError{ID: id, From: "attempts_exhausted", To: jobQueued}
	}
	j.Status = jobQueued
	j.Error = nil
	j.LeaseUntil = nil
	j.RunAfter = s.now()
	if err := s.st.UpdateJob(ctx, j); err != nil {
		return JobView{}, err
	}
	got, err := s.st.GetJob(ctx, subj.TenantID, id)
	if err != nil {
		return JobView{}, err
	}
	return jobView(got), nil
}

// ProcessJob runs one claimed issuance job: it loads the request, mints via
// issue.Service acting as the requested identity, and on success marks the job
// completed (with the certificate id) and the request issued; on failure it
// marks the job failed with a scrubbed error. The claim already incremented
// attempts, so this never double-counts.
func (s *Service) ProcessJob(ctx context.Context, job store.CertificateJob) error {
	r, err := s.st.GetRequest(ctx, job.TenantID, job.RequestID)
	if err != nil {
		return s.failJob(ctx, job, "request unavailable")
	}
	var sans []string
	if len(r.SANs) > 0 {
		_ = json.Unmarshal(r.SANs, &sans)
	}
	// Act as the requested identity so issue.Service's SR-002 entitlement holds:
	// approval already gated the request, and the identity may mint its own SVID.
	subj := authz.ServiceSubjects(job.TenantID, r.SpiffeID)
	b, ierr := s.issue.Issue(ctx, subj, issue.IssueInput{
		IssuerID: strp(r.IssuerID), SpiffeID: r.SpiffeID, CSRPEM: strp(r.CSRPEM),
		DNSSans: sans, ValiditySeconds: r.ValiditySeconds, DeliverKey: false,
	})
	if ierr != nil {
		return s.failJob(ctx, job, scrub(ierr))
	}
	certID := b.Certificate.ID
	err = s.st.Atomic(ctx, job.TenantID, func(tx repo.Store) error {
		job.Status = jobCompleted
		job.ResultCertificateID = &certID
		job.Error = nil
		job.LeaseUntil = nil
		if e := tx.UpdateJob(ctx, job); e != nil {
			return e
		}
		if e := tx.SetRequestStatus(ctx, job.TenantID, r.ID, "issued", nil, nil); e != nil {
			return e
		}
		// Hand ownership to the requester when it was a user.
		if r.RequesterKind == "user" && r.RequestedBy != "" {
			return authz.New(tx).GrantOwner(ctx, job.TenantID, authz.Certificate, certID, r.RequestedBy)
		}
		return nil
	})
	if err != nil {
		return s.failJob(ctx, job, "persisting result failed")
	}
	s.emit(ctx, audit.Event{
		TenantID: job.TenantID, EventType: audit.EnrollmentIssued, ActorKind: audit.ActorSystem, ActorID: "system",
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": r.SpiffeID, "request_id": r.ID, "job_id": job.ID},
	})
	return nil
}

// failJob records a job failure with a client-safe message and audits it.
func (s *Service) failJob(ctx context.Context, job store.CertificateJob, msg string) error {
	job.Status = jobFailed
	job.LeaseUntil = nil
	job.Error = ptrOrNil(msg)
	_ = s.st.UpdateJob(ctx, job)
	s.emit(ctx, audit.Event{
		TenantID: job.TenantID, EventType: audit.EnrollmentRefused, ActorKind: audit.ActorSystem, ActorID: "system",
		SubjectKind: audit.SubjectJob, SubjectID: job.ID, Outcome: audit.OutcomeFailed, Reason: msg,
		Details: map[string]any{"request_id": job.RequestID, "attempts": job.Attempts},
	})
	return nil
}

// scrub reduces an issuance error to a short client-safe message that never
// leaks key material, secrets or CSR contents.
func scrub(err error) string {
	var ve *ValidationError
	if errors.As(err, &ve) {
		return "invalid " + ve.Field
	}
	return "issuance failed"
}

// authorizeJob checks the caller holds action on the job's request's issuer.
// Administrators pass even when the request or issuer no longer resolves.
func (s *Service) authorizeJob(ctx context.Context, subj authz.Subjects, j store.CertificateJob, action string) error {
	r, err := s.st.GetRequest(ctx, subj.TenantID, j.RequestID)
	if err != nil {
		if subj.IsAdmin() {
			return nil
		}
		return authz.ErrForbidden
	}
	issuerID, err := s.requestIssuerID(ctx, subj.TenantID, r)
	if err != nil {
		if subj.IsAdmin() {
			return nil
		}
		return authz.ErrForbidden
	}
	return s.az.Check(ctx, subj, authz.Issuer, issuerID, action)
}

// SchedulerConfig bounds the issuance worker.
type SchedulerConfig struct {
	Interval time.Duration
	Lease    time.Duration
	Batch    int
}

// Scheduler drains the issuance job queue: a lease claim (ClaimDueJobs, system
// scope) hands each due job to exactly one instance, which processes it; a
// crash mid-issuance leaves the lease to expire and the job to be reclaimed.
type Scheduler struct {
	svc  *Service
	cfg  SchedulerConfig
	log  *slog.Logger
	tick func()
	now  func() time.Time
}

// NewScheduler wires the worker. tick fires after each batch (a test hook);
// clock/interval/lease/batch default sensibly.
func NewScheduler(svc *Service, cfg SchedulerConfig, log *slog.Logger, tick func()) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Lease <= 0 {
		cfg.Lease = time.Minute
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 50
	}
	if tick == nil {
		tick = func() {}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{svc: svc, cfg: cfg, log: log, tick: tick, now: svc.now}
}

// SetClock injects the clock (tests).
func (w *Scheduler) SetClock(now func() time.Time) {
	if now != nil {
		w.now = now
	}
}

// Once claims and processes one batch of due jobs; returns the number processed
// without a processing error.
func (w *Scheduler) Once(ctx context.Context) (int, error) {
	due, err := w.svc.st.ClaimDueJobs(ctx, w.now(), w.cfg.Lease, w.cfg.Batch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, j := range due {
		if err := w.svc.ProcessJob(ctx, j); err != nil {
			w.log.Warn("job processing failed; will retry after the lease", "job", j.ID, "err", err)
			continue
		}
		n++
	}
	w.tick()
	return n, nil
}

// Run processes due jobs every interval until ctx ends.
func (w *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		if _, err := w.Once(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("scheduler claim failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
