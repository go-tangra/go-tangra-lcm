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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// ErrForbidden is returned when a caller (or an enrollment token) is not
// entitled to the requested SPIFFE identity. It aliases authz.ErrForbidden so
// callers may match either.
var ErrForbidden = authz.ErrForbidden

// Enrollment-token refusal reasons: a closed vocabulary returned verbatim to the
// enrolling workload so an operator can see WHY a join failed. The first four
// are the auth service's verdict on the token; the last two are lcm's own
// refusal of an authentic token. None carries the token or any secret.
const (
	ReasonTokenExpired        = "enrollment_token_expired"
	ReasonTokenNotYetValid    = "enrollment_token_not_yet_valid"
	ReasonTokenUsed           = "enrollment_token_used"
	ReasonTokenInvalid        = "enrollment_token_invalid"
	ReasonSpiffeIDNotAllowed  = "enrollment_spiffe_id_not_allowed"
	ReasonTrustDomainMismatch = "enrollment_trust_domain_mismatch"
)

// RefusalError refuses a token enrollment with a stable Reason and an optional
// client-safe Detail. It unwraps to ErrForbidden so errors.Is(err, ErrForbidden)
// still holds for every refusal.
type RefusalError struct {
	Reason string
	Detail map[string]any
}

func (e *RefusalError) Error() string { return "enroll: " + e.Reason }

func (e *RefusalError) Unwrap() error { return ErrForbidden }

// TokenRefused reports whether the token itself was refused (the caller is
// unauthenticated) rather than the identity it asked for (forbidden).
func (e *RefusalError) TokenRefused() bool {
	switch e.Reason {
	case ReasonTokenExpired, ReasonTokenNotYetValid, ReasonTokenUsed, ReasonTokenInvalid:
		return true
	}
	return false
}

// ErrVerifierUnavailable marks a TokenVerifier failure that is not a verdict on
// the token (auth unreachable, jti burn failed): the enrollment is retryable and
// answers temporarily_unavailable, never a refusal reason.
var ErrVerifierUnavailable = errors.New("enroll: enrollment token verifier unavailable")

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

// refusal explains why the grant does not authorise an id in trustDomain: a
// trust domain the grant never names (a misconfigured workload, e.g. verax.net
// instead of infra.verax.net) is told apart from a path it does not name. The
// expected trust domain is the grant's own (the caller holds the token, and
// trust domains are public), never a secret.
func (g EnrollGrant) refusal(trustDomain string) *RefusalError {
	var domains []string
	for _, p := range g.SpiffePaths {
		id, perr := csr.ParseSPIFFEID(p)
		if perr != nil {
			continue
		}
		td := id.TrustDomain
		if td == trustDomain {
			return &RefusalError{Reason: ReasonSpiffeIDNotAllowed}
		}
		if !slices.Contains(domains, td) {
			domains = append(domains, td)
		}
	}
	switch len(domains) {
	case 0:
		return &RefusalError{Reason: ReasonSpiffeIDNotAllowed}
	case 1:
		return &RefusalError{Reason: ReasonTrustDomainMismatch, Detail: map[string]any{"expected_trust_domain": domains[0]}}
	}
	return &RefusalError{Reason: ReasonTrustDomainMismatch, Detail: map[string]any{"expected_trust_domains": domains}}
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
	sid, err := csr.ParseSPIFFEID(in.SpiffeID)
	if err != nil {
		return EnrollResult{}, invalid("spiffe_id", "invalid SPIFFE ID")
	}

	tenant := subj.TenantID
	actor := subj                     // subject used for issuance + audit actor
	actorID := subj.ActorID()         // audit actor id / request requested_by
	requesterKind := subj.ActorKind() // user | service (token overrides below)

	if in.EnrollmentToken != "" {
		grant, verr := s.tok.VerifyEnrollment(ctx, in.EnrollmentToken)
		if verr != nil {
			if errors.Is(verr, ErrVerifierUnavailable) {
				// No verdict on the token: retryable, never a refusal.
				return EnrollResult{}, fmt.Errorf("enroll: verify enrollment token: %w", verr)
			}
			// Replayed, expired or unknown token: single-use is the verifier's
			// contract, and we never fall back to a shared secret. A verdict
			// without a known reason stays opaque (enrollment_token_invalid).
			var re *RefusalError
			if !errors.As(verr, &re) || !re.TokenRefused() {
				re = &RefusalError{Reason: ReasonTokenInvalid}
			}
			s.refuse(ctx, tenant, subj.ActorKind(), actorID, in.SpiffeID, "enrollment token rejected: "+re.Reason)
			return EnrollResult{}, re
		}
		if !grant.authorises(in.SpiffeID) {
			// The grant is authoritative, but only for the identities it names.
			re := grant.refusal(sid.TrustDomain)
			s.refuse(ctx, orTenant(grant.TenantID, tenant), audit.ActorService, in.SpiffeID, in.SpiffeID,
				"token does not authorise the requested identity: "+re.Reason)
			return EnrollResult{}, re
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
