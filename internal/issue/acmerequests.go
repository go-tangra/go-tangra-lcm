package issue

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Generic (ACME) request states: an order runs processing -> issued|failed.
const (
	requestProcessing = "processing"
	requestIssued     = "issued"
	requestFailed     = "failed"
)

// ACMEOrder is an accepted ACME order, recorded as a generic certificate
// request so it appears with its outcome on the requests listing.
type ACMEOrder struct {
	RequestID string
	Domains   []string // normalised
}

// BeginACME validates an ACME order synchronously (issuer, permission and
// domains; no network calls) and records it as a generic certificate request
// in the processing state. The caller then runs ObtainACMEFor and FinishACME.
func (s *Service) BeginACME(ctx context.Context, subj authz.Subjects, issuerID string, domains []string) (ACMEOrder, error) {
	if err := s.PrecheckACME(ctx, subj, issuerID); err != nil {
		return ACMEOrder{}, err
	}
	names, err := validateACMEDomains(domains)
	if err != nil {
		return ACMEOrder{}, err
	}
	sansJSON, err := json.Marshal(names)
	if err != nil {
		return ACMEOrder{}, err
	}
	row := store.CertificateRequest{
		ID: store.NewID(), TenantID: subj.TenantID, IssuerID: &issuerID, Kind: "generic", SANs: sansJSON,
		RequestedBy: subj.ActorID(), RequesterKind: subj.ActorKind(), Status: requestProcessing,
	}
	if err := s.st.InsertRequest(ctx, row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ACMEOrder{}, invalid("issuer_id", "issuer not found")
		}
		return ACMEOrder{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.CertificateRequested, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectRequest, SubjectID: row.ID, SubjectName: names[0], Outcome: audit.OutcomeOK,
		Details: map[string]any{"domains": strings.Join(names, ","), "issuer_id": issuerID, "kind": "generic", "requester_kind": subj.ActorKind()},
	})
	return ACMEOrder{RequestID: row.ID, Domains: names}, nil
}

// FinishACME ends an order's request: issued and linked to certificateID when
// orderErr is nil, else failed with the order's client-safe reason.
func (s *Service) FinishACME(ctx context.Context, subj authz.Subjects, requestID, certificateID string, orderErr error) error {
	if orderErr != nil {
		reason := FailReason(orderErr)
		return s.st.CompleteRequest(ctx, subj.TenantID, requestID, requestFailed, nil, &reason)
	}
	return s.st.CompleteRequest(ctx, subj.TenantID, requestID, requestIssued, &certificateID, nil)
}

// validateACMEDomains normalises an order's DNS names (lowercase, trimmed,
// trailing dot dropped, duplicates removed) and refuses what an ACME CA would
// reject, naming the offending domain: malformed names, more than
// acme.MaxDomains names, and a name already covered by a wildcard in the same
// order (a wildcard covers exactly one label).
func validateACMEDomains(in []string) ([]string, error) {
	names := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !seen[d] {
			seen[d] = true
			names = append(names, d)
		}
	}
	if len(names) == 0 {
		return nil, invalid("domains", "at least one DNS domain is required")
	}
	if len(names) > acme.MaxDomains {
		return nil, invalid("domains", "at most "+strconv.Itoa(acme.MaxDomains)+" domains per order")
	}
	for _, d := range names {
		if msg := domainProblem(d); msg != "" {
			return nil, invalid("domains", "domain \""+d+"\" "+msg)
		}
	}
	for _, d := range names {
		if _, parent, ok := strings.Cut(d, "."); ok && !strings.HasPrefix(d, "*.") && seen["*."+parent] {
			return nil, invalid("domains", "domain \""+d+"\" is already covered by the wildcard \"*."+parent+"\"; remove one of them")
		}
	}
	return names, nil
}

// domainProblem describes why a normalised name is not a valid ACME DNS
// identifier, or "" when it is.
func domainProblem(d string) string {
	if len(d) > 253 {
		return "is longer than 253 characters"
	}
	base := strings.TrimPrefix(d, "*.")
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "needs at least two labels (e.g. example.org)"
	}
	for _, l := range labels {
		if msg := labelProblem(l); msg != "" {
			return msg
		}
	}
	return ""
}

func labelProblem(l string) string {
	switch {
	case l == "":
		return "has an empty label"
	case l == "*":
		return "may only use a wildcard as its whole first label (*.example.org)"
	case len(l) > 63:
		return "has a label longer than 63 characters"
	case l[0] == '-' || l[len(l)-1] == '-':
		return "has a label starting or ending with a hyphen"
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			if c == '*' {
				return "may only use a wildcard as its whole first label (*.example.org)"
			}
			return "contains a character other than letters, digits and hyphens"
		}
	}
	return ""
}

func ptrOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
