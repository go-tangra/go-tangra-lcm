// Package renew runs the distributed certificate-renewal scheduler: it scans
// for certificates approaching expiry, reissues them through the issuance
// service (reusing the same SPIFFE identity and superseding the old row), and
// publishes a "renewed" live event per success. Every scan runs under the
// system scope; the FOR UPDATE SKIP LOCKED claim in the store's DueForRenewal
// is the distributed lease that lets many instances share the work without
// renewing the same certificate twice (research R7).
package renew

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// systemSpiffe is the identity the scheduler acts as when reissuing on behalf
// of a tenant's certificate; it carries no user and no roles, so only the
// certificate's own tenant-wide grants (and admin implicit ownership) apply.
const systemSpiffe = "spiffe://system/lcm/renew"

// maxBatch bounds the certificates a single pass claims and renews. The store's
// SKIP LOCKED claim already partitions work across instances; this only caps the
// per-tick fan-out so one pass cannot monopolise the workers.
const maxBatch = 256

// Publisher decouples the scheduler from the SSE hub / gRPC event fan-out. The
// app passes an adapter that forwards to the live-event hub; tests pass a fake
// that records the events. eventType is always "renewed".
type Publisher interface {
	Publish(ctx context.Context, tenantID, eventType, certificateID, spiffeID string, notAfter time.Time)
}

// Renewer reissues a certificate by id under the given subjects, returning the
// fresh bundle. *issue.Service satisfies it.
type Renewer interface {
	Renew(ctx context.Context, subj authz.Subjects, certID string) (issue.Bundle, error)
}

// Config bounds the scheduler.
type Config struct {
	Interval           time.Duration // tick period
	Workers            int           // per-pass renewal concurrency
	ShortLivedFraction float64       // renew short SVIDs at this fraction of TTL remaining
	LongLivedWindow    time.Duration // renew longer certificates this far before expiry
}

// Scheduler scans for and renews due certificates.
type Scheduler struct {
	st    repo.Store
	r     Renewer
	pub   Publisher
	cfg   Config
	log   *slog.Logger
	clock func() time.Time
	tick  func()
}

// Compile-time guarantee that the issuance service is a Renewer.
var _ Renewer = (*issue.Service)(nil)

// NewScheduler wires the scheduler. clock defaults to time.Now when nil; tick is
// an optional health heartbeat called once per pass.
func NewScheduler(st repo.Store, r Renewer, pub Publisher, cfg Config, log *slog.Logger, clock func() time.Time, tick func()) *Scheduler {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.ShortLivedFraction <= 0 || cfg.ShortLivedFraction >= 1 {
		cfg.ShortLivedFraction = 0.5
	}
	if cfg.LongLivedWindow <= 0 {
		cfg.LongLivedWindow = 30 * 24 * time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	if clock == nil {
		clock = time.Now
	}
	if tick == nil {
		tick = func() {}
	}
	return &Scheduler{st: st, r: r, pub: pub, cfg: cfg, log: log, clock: clock, tick: tick}
}

// window returns how far before expiry the certificate is renewed. Short-lived
// SVIDs (whole lifetime no longer than LongLivedWindow) renew at a fraction of
// their TTL remaining; longer certificates renew at the fixed LongLivedWindow,
// or (1-fraction) of their TTL when that is larger.
func (s *Scheduler) window(cert store.IssuedCertificate) time.Duration {
	totalTTL := cert.NotAfter.Sub(cert.NotBefore)
	if totalTTL <= 0 {
		return s.cfg.LongLivedWindow
	}
	if totalTTL <= s.cfg.LongLivedWindow {
		// Short-lived SVID: renew when remaining <= fraction * totalTTL.
		return time.Duration(float64(totalTTL) * s.cfg.ShortLivedFraction)
	}
	// Long-lived: the larger of the fixed window and (1-fraction) of the TTL.
	w := time.Duration(float64(totalTTL) * (1 - s.cfg.ShortLivedFraction))
	if s.cfg.LongLivedWindow > w {
		w = s.cfg.LongLivedWindow
	}
	return w
}

// Due reports whether the certificate should be renewed at now: now has reached
// renewAt = notAfter - window(cert).
func (s *Scheduler) Due(cert store.IssuedCertificate, now time.Time) bool {
	renewAt := cert.NotAfter.Add(-s.window(cert))
	return !now.Before(renewAt)
}

// maxWindow is an upper bound on window(cert) over every renewable certificate,
// so a DueForRenewal scan up to now+maxWindow never misses a due certificate.
func (s *Scheduler) maxWindow() time.Duration {
	maxTTL := time.Duration(issue.MaxValiditySeconds) * time.Second
	w := time.Duration(float64(maxTTL) * (1 - s.cfg.ShortLivedFraction))
	if s.cfg.LongLivedWindow > w {
		w = s.cfg.LongLivedWindow
	}
	return w
}

// RunOnce claims the certificates approaching expiry under the system scope,
// renews the ones whose renewal window has opened, and publishes a "renewed"
// event per success. It never renews the same certificate twice in one pass
// (the claim returns each row once) or across passes (Renew stamps
// superseded_by, so the next scan skips the row - SC-003). Per-certificate
// errors are logged and skipped; the batch is not aborted.
func (s *Scheduler) RunOnce(ctx context.Context) (int, error) {
	now := s.clock()
	rows, err := s.st.DueForRenewal(ctx, now, now.Add(s.maxWindow()), maxBatch)
	if err != nil {
		return 0, err
	}
	// Apply the precise per-certificate window; the store scan is a coarse
	// notAfter filter.
	due := make([]store.IssuedCertificate, 0, len(rows))
	for _, c := range rows {
		if s.Due(c, now) {
			due = append(due, c)
		}
	}
	if len(due) == 0 {
		return 0, nil
	}

	var renewed atomic.Int64
	jobs := make(chan store.IssuedCertificate)
	var wg sync.WaitGroup
	workers := s.cfg.Workers
	if workers > len(due) {
		workers = len(due)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cert := range jobs {
				if s.renewOne(ctx, cert) {
					renewed.Add(1)
				}
			}
		}()
	}
	for _, cert := range due {
		if ctx.Err() != nil {
			break
		}
		jobs <- cert
	}
	close(jobs)
	wg.Wait()
	return int(renewed.Load()), nil
}

// renewOne reissues a single certificate as the system for its tenant and
// publishes the "renewed" event on success. It reports whether it renewed.
func (s *Scheduler) renewOne(ctx context.Context, cert store.IssuedCertificate) bool {
	subj := authz.ServiceSubjects(cert.TenantID, systemSpiffe)
	b, err := s.r.Renew(ctx, subj, cert.ID)
	if err != nil {
		// Scrubbed: only the identifiers, never key or certificate material.
		s.log.Warn("scheduled renewal failed; the lease expires and the next scan retries",
			"certificate", cert.ID, "tenant", cert.TenantID, "err", err)
		return false
	}
	if s.pub != nil {
		s.pub.Publish(ctx, cert.TenantID, "renewed", b.Certificate.ID, b.Certificate.SpiffeID, b.Certificate.NotAfter)
	}
	return true
}

// Run ticks every Config.Interval, renewing due certificates until ctx ends. The
// heartbeat runs each pass; a claim error is logged and the loop continues.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("renewal scan failed", "err", err)
		}
		s.tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
