// Package enroll is the enrollment service layer of lcm: it turns an
// enrollment request (a platform identity, or a short-lived single-use
// enrollment token that authorises a SPIFFE identity) into either an inline
// certificate bundle (auto-approve) or a pending certificate request that an
// operator approves, which enqueues an asynchronous issuance job. The actual
// signing is delegated to issue.Service (SR-002 entitlement, audit, key
// hygiene are enforced there); enroll never re-implements issuance and never
// trusts a static shared secret — the only credential it accepts is a token
// verified by the TokenVerifier, and a token is authoritative only for the
// SPIFFE id its grant names.
package enroll

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/repo"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// ErrForbidden is returned when a caller (or an enrollment token) is not
// entitled to the requested SPIFFE identity. It aliases authz.ErrForbidden so
// callers may match either.
var ErrForbidden = authz.ErrForbidden

// ValidationError is a client-safe rejection carrying the offending field.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return "enroll: " + e.Field + ": " + e.Message
	}
	return "enroll: " + e.Message
}

func invalid(field, msg string) error { return &ValidationError{Field: field, Message: msg} }

// ConflictError refuses a request/job state transition that the state machine
// does not allow. It unwraps to store.ErrConflict so errors.Is(err,
// store.ErrConflict) also holds.
type ConflictError struct {
	ID   string
	From string
	To   string
}

func (e *ConflictError) Error() string {
	return "enroll: cannot move " + e.ID + " from " + e.From + " to " + e.To
}

func (e *ConflictError) Unwrap() error { return store.ErrConflict }

// EnrollGrant is what a verified enrollment token authorises: a tenant and the
// set of SPIFFE identities the token may enroll (auth tokens authorise one or
// more). The verifier's contract makes a token single-use and short-lived;
// enroll treats the grant as authoritative but still refuses any SPIFFE id the
// grant does not name.
type EnrollGrant struct {
	TenantID    string
	SpiffePaths []string
}

// authorises reports whether the grant permits enrolling spiffeID.
func (g EnrollGrant) authorises(spiffeID string) bool {
	for _, p := range g.SpiffePaths {
		if p == spiffeID {
			return true
		}
	}
	return false
}

// TokenVerifier decouples enroll from the auth service: it exchanges an
// enrollment token for the grant it authorises, or an error (expired, replayed,
// unknown). Wired to the auth service in production; a fake in tests.
type TokenVerifier interface {
	VerifyEnrollment(ctx context.Context, token string) (EnrollGrant, error)
}

// Config tunes enrollment behaviour.
type Config struct {
	// AutoApprove issues inline instead of creating a pending request.
	AutoApprove bool
	// MaxAttempts bounds issuance retries per job (defaults to 5).
	MaxAttempts int
}

// Service enrolls identities, manages certificate requests and drives the
// issuance job queue.
type Service struct {
	st    repo.Store
	issue *issue.Service
	az    *authz.Authorizer
	audit *audit.Writer
	tok   TokenVerifier
	cfg   Config
	now   func() time.Time
}

// New wires the service. clock defaults to time.Now when nil; MaxAttempts
// defaults to 5 when non-positive.
func New(st repo.Store, iss *issue.Service, az *authz.Authorizer, aw *audit.Writer, tv TokenVerifier, cfg Config, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	return &Service{st: st, issue: iss, az: az, audit: aw, tok: tv, cfg: cfg, now: clock}
}

// SetClock injects the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// EnrollInput is an enrollment request. EnrollmentToken, when present, is
// verified and its grant becomes authoritative for the tenant and identity.
type EnrollInput struct {
	SpiffeID        string
	CSRPEM          string
	EnrollmentToken string
}

// EnrollResult is the outcome of Enroll. In auto-approve mode Bundle carries
// the inline issuance (Status "issued"); otherwise RequestID names the pending
// request awaiting approval (Status "pending", 202-style).
type EnrollResult struct {
	Status    string        `json:"status"`
	RequestID string        `json:"request_id,omitempty"`
	Bundle    *issue.Bundle `json:"bundle,omitempty"`
}

// Enroll authorises the request (token grant, or the platform identity delegated
// to issue.Service), then either issues inline or creates a pending request.
func (s *Service) Enroll(ctx context.Context, subj authz.Subjects, in EnrollInput) (EnrollResult, error) {
	if _, err := csr.ParseSPIFFEID(in.SpiffeID); err != nil {
		return EnrollResult{}, invalid("spiffe_id", "invalid SPIFFE ID")
	}

	tenant := subj.TenantID
	actor := subj                     // subject used for issuance + audit actor
	actorID := subj.ActorID()         // audit actor id / request requested_by
	requesterKind := subj.ActorKind() // user | service (token overrides below)

	if in.EnrollmentToken != "" {
		grant, verr := s.tok.VerifyEnrollment(ctx, in.EnrollmentToken)
		if verr != nil {
			// Replayed, expired or unknown token: single-use is the verifier's
			// contract, and we never fall back to a shared secret.
			s.refuse(ctx, tenant, subj.ActorKind(), actorID, in.SpiffeID, "enrollment token rejected")
			return EnrollResult{}, ErrForbidden
		}
		if !grant.authorises(in.SpiffeID) {
			// The grant is authoritative, but only for the identities it names.
			s.refuse(ctx, orTenant(grant.TenantID, tenant), audit.ActorService, in.SpiffeID, in.SpiffeID,
				"token does not authorise the requested identity")
			return EnrollResult{}, ErrForbidden
		}
		tenant = grant.TenantID
		actor = authz.ServiceSubjects(tenant, in.SpiffeID)
		actorID = in.SpiffeID
		requesterKind = requesterToken
	}

	if in.CSRPEM != "" {
		if _, perr := csr.ParseCSR([]byte(in.CSRPEM)); perr != nil {
			return EnrollResult{}, invalid("csr", "certificate request rejected")
		}
	}

	if s.cfg.AutoApprove {
		b, ierr := s.issue.Issue(ctx, actor, issue.IssueInput{
			SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM, DeliverKey: in.CSRPEM == "",
		})
		if ierr != nil {
			s.refuse(ctx, tenant, actor.ActorKind(), actorID, in.SpiffeID, "issuance refused")
			return EnrollResult{}, ierr
		}
		s.emit(ctx, audit.Event{
			TenantID: tenant, EventType: audit.EnrollmentIssued, ActorKind: actor.ActorKind(), ActorID: actorID,
			SubjectKind: audit.SubjectCertificate, SubjectID: b.Certificate.ID, Outcome: audit.OutcomeOK,
			Details: map[string]any{"spiffe_id": in.SpiffeID, "issuer_id": b.Certificate.IssuerID},
		})
		return EnrollResult{Status: statusIssued, Bundle: &b}, nil
	}

	rv, cerr := s.createRequest(ctx, tenant, actorID, requesterKind, RequestInput{
		SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM,
	})
	if cerr != nil {
		return EnrollResult{}, cerr
	}
	return EnrollResult{Status: statusPending, RequestID: rv.ID}, nil
}

// Statuses and requester kinds.
const (
	statusIssued   = "issued"
	statusPending  = "pending"
	requesterToken = "token"
)

// refuse records an enrollment_refused audit event best-effort.
func (s *Service) refuse(ctx context.Context, tenant, actorKind, actorID, spiffeID, reason string) {
	if tenant == "" {
		return
	}
	s.emit(ctx, audit.Event{
		TenantID: tenant, EventType: audit.EnrollmentRefused, ActorKind: actorKind, ActorID: actorID,
		SubjectKind: audit.SubjectRequest, Outcome: audit.OutcomeRefused, Reason: reason,
		Details: map[string]any{"spiffe_id": spiffeID},
	})
}

// emit records an audit event best-effort.
func (s *Service) emit(ctx context.Context, e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Record(ctx, e)
	}
}

func orTenant(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// encodeCursor / decodeCursor format a (time, id) page cursor.
func encodeCursor(ts time.Time, id string) string {
	return ts.UTC().Format(time.RFC3339Nano) + "|" + id
}

func decodeCursor(c string) (time.Time, string, error) {
	if c == "" {
		return time.Time{}, "", nil
	}
	for i := 0; i < len(c); i++ {
		if c[i] == '|' && i > 0 {
			ts, err := time.Parse(time.RFC3339Nano, c[:i])
			if err != nil {
				break
			}
			return ts, c[i+1:], nil
		}
	}
	return time.Time{}, "", invalid("cursor", "bad cursor")
}
