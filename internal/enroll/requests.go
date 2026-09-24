package enroll

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// RequestInput is a certificate-request application.
type RequestInput struct {
	IssuerID        string
	SpiffeID        string
	CSRPEM          string
	ValiditySeconds int64
	DNSSans         []string
}

// RequestView is a certificate request as returned to clients. It never
// carries the CSR PEM (HasCSR reports its presence).
type RequestView struct {
	ID              string   `json:"id"`
	SpiffeID        string   `json:"spiffe_id"`
	IssuerID        string   `json:"issuer_id,omitempty"`
	Status          string   `json:"status"`
	SANs            []string `json:"sans"`
	ValiditySeconds int64    `json:"validity_seconds"`
	RequestedBy     string   `json:"requested_by"`
	RequesterKind   string   `json:"requester_kind"`
	Approver        string   `json:"approver,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	HasCSR          bool     `json:"has_csr"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

func requestView(r store.CertificateRequest) RequestView {
	var sans []string
	if len(r.SANs) > 0 {
		_ = json.Unmarshal(r.SANs, &sans)
	}
	if sans == nil {
		sans = []string{}
	}
	return RequestView{
		ID: r.ID, SpiffeID: r.SpiffeID, IssuerID: strp(r.IssuerID), Status: r.Status,
		SANs: sans, ValiditySeconds: r.ValiditySeconds, RequestedBy: r.RequestedBy, RequesterKind: r.RequesterKind,
		Approver: strp(r.Approver), Reason: strp(r.Reason), HasCSR: r.CSRPEM != nil,
		CreatedAt: r.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		UpdatedAt: r.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
}

// CreateRequest stores a pending certificate request for the caller's identity.
func (s *Service) CreateRequest(ctx context.Context, subj authz.Subjects, in RequestInput) (RequestView, error) {
	return s.createRequest(ctx, subj.TenantID, subj.ActorID(), subj.ActorKind(), in)
}

// createRequest validates and stores a pending request. requestedBy/requesterKind
// name the actor (a token enrollment records kind "token").
func (s *Service) createRequest(ctx context.Context, tenant, requestedBy, requesterKind string, in RequestInput) (RequestView, error) {
	sid, err := csr.ParseSPIFFEID(in.SpiffeID)
	if err != nil {
		return RequestView{}, invalid("spiffe_id", "invalid SPIFFE ID")
	}
	if in.CSRPEM != "" {
		if _, perr := csr.ParseCSR([]byte(in.CSRPEM)); perr != nil {
			return RequestView{}, invalid("csr", "certificate request rejected")
		}
	}
	// Pin the issuer when known so approval checks the right authority; otherwise
	// resolve the trust domain's default, leaving it unset when there is none.
	issuerID := in.IssuerID
	if issuerID == "" {
		if def, derr := s.st.DefaultIssuer(ctx, tenant, sid.TrustDomain); derr == nil {
			issuerID = def.ID
		}
	}
	sansJSON, err := json.Marshal(sansList(in.DNSSans))
	if err != nil {
		return RequestView{}, err
	}
	row := store.CertificateRequest{
		ID: store.NewID(), TenantID: tenant, IssuerID: ptrOrNil(issuerID), SpiffeID: in.SpiffeID,
		SANs: sansJSON, CSRPEM: ptrOrNil(in.CSRPEM), ValiditySeconds: in.ValiditySeconds,
		RequestedBy: requestedBy, RequesterKind: requesterKind, Status: statusPending,
	}
	if err := s.st.InsertRequest(ctx, row); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return RequestView{}, invalid("issuer_id", "unknown issuer")
		}
		return RequestView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: tenant, EventType: audit.CertificateRequested, ActorKind: actorKind(requesterKind), ActorID: requestedBy,
		SubjectKind: audit.SubjectRequest, SubjectID: row.ID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": in.SpiffeID, "requester_kind": requesterKind},
	})
	got, err := s.st.GetRequest(ctx, tenant, row.ID)
	if err != nil {
		return RequestView{}, err
	}
	return requestView(got), nil
}

// GetRequest returns a request the caller may read: its requester, or anyone
// holding read on its issuer.
func (s *Service) GetRequest(ctx context.Context, subj authz.Subjects, id string) (RequestView, error) {
	r, err := s.st.GetRequest(ctx, subj.TenantID, id)
	if err != nil {
		return RequestView{}, err
	}
	if err := s.authorizeReadRequest(ctx, subj, r); err != nil {
		return RequestView{}, err
	}
	return requestView(r), nil
}

// RequestFilter selects requests for a listing.
type RequestFilter struct {
	Status string
	Cursor string
	Limit  int
}

// ListRequests pages requests the caller may read, newest first.
func (s *Service) ListRequests(ctx context.Context, subj authz.Subjects, f RequestFilter) ([]RequestView, string, error) {
	ts, id, err := decodeCursor(f.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.st.ListRequests(ctx, subj.TenantID, store.RequestFilter{Status: f.Status, CursorTS: ts, CursorID: id, Limit: limit})
	if err != nil {
		return nil, "", err
	}
	out := make([]RequestView, 0, len(rows))
	for _, r := range rows {
		if s.authorizeReadRequest(ctx, subj, r) != nil {
			continue
		}
		out = append(out, requestView(r))
	}
	next := ""
	if len(rows) == limit {
		last := rows[len(rows)-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

// ApproveRequest moves a pending request to approved and enqueues an issuance
// job. The caller must hold manage (write) on the request's issuer.
func (s *Service) ApproveRequest(ctx context.Context, subj authz.Subjects, id, reason string) (RequestView, error) {
	r, err := s.st.GetRequest(ctx, subj.TenantID, id)
	if err != nil {
		return RequestView{}, err
	}
	issuerID, err := s.requestIssuerID(ctx, subj.TenantID, r)
	if err != nil {
		return RequestView{}, err
	}
	if err := s.az.Check(ctx, subj, authz.Issuer, issuerID, authz.Write); err != nil {
		return RequestView{}, err
	}
	if r.Status != statusPending {
		return RequestView{}, &ConflictError{ID: id, From: r.Status, To: "approved"}
	}
	approver := subj.ActorID()
	jobID := store.NewID()
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if e := tx.SetRequestStatus(ctx, subj.TenantID, id, "approved", ptrOrNil(approver), ptrOrNil(reason)); e != nil {
			return e
		}
		return tx.InsertJob(ctx, store.CertificateJob{
			ID: jobID, TenantID: subj.TenantID, RequestID: id, Type: "issue", Status: "queued",
			MaxAttempts: s.cfg.MaxAttempts, RunAfter: s.now(),
		})
	})
	if err != nil {
		return RequestView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.RequestApproved, ActorKind: subj.ActorKind(), ActorID: approver,
		SubjectKind: audit.SubjectRequest, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": r.SpiffeID, "job_id": jobID},
	})
	got, err := s.st.GetRequest(ctx, subj.TenantID, id)
	if err != nil {
		return RequestView{}, err
	}
	return requestView(got), nil
}

// RejectRequest moves a pending request to rejected. The caller must hold
// manage (write) on the request's issuer.
func (s *Service) RejectRequest(ctx context.Context, subj authz.Subjects, id, reason string) (RequestView, error) {
	r, err := s.st.GetRequest(ctx, subj.TenantID, id)
	if err != nil {
		return RequestView{}, err
	}
	issuerID, err := s.requestIssuerID(ctx, subj.TenantID, r)
	if err != nil {
		return RequestView{}, err
	}
	if err := s.az.Check(ctx, subj, authz.Issuer, issuerID, authz.Write); err != nil {
		return RequestView{}, err
	}
	if r.Status != statusPending {
		return RequestView{}, &ConflictError{ID: id, From: r.Status, To: "rejected"}
	}
	rejector := subj.ActorID()
	if err := s.st.SetRequestStatus(ctx, subj.TenantID, id, "rejected", ptrOrNil(rejector), ptrOrNil(reason)); err != nil {
		return RequestView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.RequestRejected, ActorKind: subj.ActorKind(), ActorID: rejector,
		SubjectKind: audit.SubjectRequest, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": r.SpiffeID},
	})
	got, err := s.st.GetRequest(ctx, subj.TenantID, id)
	if err != nil {
		return RequestView{}, err
	}
	return requestView(got), nil
}

// authorizeReadRequest allows the request's own requester, or anyone holding
// read on the request's issuer.
func (s *Service) authorizeReadRequest(ctx context.Context, subj authz.Subjects, r store.CertificateRequest) error {
	if actor := subj.ActorID(); actor != "" && r.RequestedBy == actor {
		return nil
	}
	issuerID, err := s.requestIssuerID(ctx, subj.TenantID, r)
	if err != nil {
		return authz.ErrForbidden
	}
	return s.az.Check(ctx, subj, authz.Issuer, issuerID, authz.Read)
}

// requestIssuerID resolves the issuer a request is (or would be) issued from:
// its pinned issuer, else the trust domain's default. store.ErrNotFound when
// neither exists.
func (s *Service) requestIssuerID(ctx context.Context, tenant string, r store.CertificateRequest) (string, error) {
	if r.IssuerID != nil && *r.IssuerID != "" {
		return *r.IssuerID, nil
	}
	sid, err := csr.ParseSPIFFEID(r.SpiffeID)
	if err != nil {
		return "", store.ErrNotFound
	}
	def, err := s.st.DefaultIssuer(ctx, tenant, sid.TrustDomain)
	if err != nil {
		return "", err
	}
	return def.ID, nil
}

// actorKind maps a requester kind to a valid audit actor kind (a token
// enrollment is a service workload).
func actorKind(requesterKind string) string {
	if requesterKind == requesterToken || requesterKind == audit.ActorService {
		return audit.ActorService
	}
	return audit.ActorUser
}

// sansList normalises a possibly-nil slice to a non-nil slice for JSON.
func sansList(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
