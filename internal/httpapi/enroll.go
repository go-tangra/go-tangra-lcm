package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
)

// EnrollDeps are the services behind the enrollment, request and job routes.
type EnrollDeps struct {
	Enroll *enroll.Service
	Perms  PermissionChecker
}

// enrollError maps enroll-service errors onto refusals.
func enrollError(err error) error {
	var ve *enroll.ValidationError
	var ce *enroll.ConflictError
	switch {
	case errors.As(err, &ve):
		return &DetailError{Err: ErrValidation, Detail: map[string]any{"field": ve.Field, "message": ve.Message}}
	case errors.As(err, &ce):
		return ErrConflict
	}
	return domainError(err)
}

// enrollReadError masks forbidden as not_found for single reads (SR-005).
func enrollReadError(err error) error {
	if errors.Is(err, authz.ErrForbidden) {
		return ErrNotFound
	}
	return enrollError(err)
}

// RegisterEnroll mounts the enrollment, certificate-request and job routes.
func (s *Server) RegisterEnroll(d EnrollDeps) {
	s.MustHandle("POST", Prefix+"/enroll", func(w http.ResponseWriter, r *http.Request) {
		// Public route: a cold workload has no platform token. The single-use
		// enrollment token in the body is the sole credential; the tenant and
		// actor identity come from the verified token grant (never a caller).
		var in struct {
			SpiffeID        string `json:"spiffe_id"`
			CSRPEM          string `json:"csr_pem"`
			EnrollmentToken string `json:"enrollment_token"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if in.EnrollmentToken == "" {
			Fail(w, r, nil, ErrUnauthenticated)
			return
		}
		subj := authz.ServiceSubjects("", in.SpiffeID)
		res, err := d.Enroll.Enroll(r.Context(), subj, enroll.EnrollInput{SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM, EnrollmentToken: in.EnrollmentToken})
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		if res.Status == "issued" && res.Bundle != nil {
			WriteJSON(w, http.StatusOK, bundleJSON(*res.Bundle))
			return
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{"status": "pending", "request_id": res.RequestID})
	})

	// ---- certificate requests
	s.MustHandle("GET", Prefix+"/requests", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		items, next, err := d.Enroll.ListRequests(r.Context(), subj, enroll.RequestFilter{Status: q.Get("status"), Cursor: q.Get("cursor"), Limit: limitParam(r)})
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
	})
	s.MustHandle("POST", Prefix+"/requests", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			IssuerID        string   `json:"issuer_id"`
			SpiffeID        string   `json:"spiffe_id"`
			CSRPEM          string   `json:"csr_pem"`
			Subject         string   `json:"subject"`
			ValiditySeconds int64    `json:"validity_seconds"`
			DNSSans         []string `json:"dns_sans"`
			DeliverKey      bool     `json:"deliver_key"` // accepted (the shared IssueInput schema carries it); a request never delivers a key inline
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Enroll.CreateRequest(r.Context(), subj, enroll.RequestInput{IssuerID: in.IssuerID, SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM, ValiditySeconds: in.ValiditySeconds, DNSSans: in.DNSSans})
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("GET", Prefix+"/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Enroll.GetRequest(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, enrollReadError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		_ = DecodeJSON(r, &in, 0)
		out, err := d.Enroll.ApproveRequest(r.Context(), subj, r.PathValue("id"), in.Reason)
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/requests/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		_ = DecodeJSON(r, &in, 0)
		out, err := d.Enroll.RejectRequest(r.Context(), subj, r.PathValue("id"), in.Reason)
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})

	// ---- jobs
	s.MustHandle("GET", Prefix+"/jobs", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		items, next, err := d.Enroll.ListJobs(r.Context(), subj, enroll.JobFilter{Status: q.Get("status"), Cursor: q.Get("cursor"), Limit: limitParam(r)})
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
	})
	s.MustHandle("GET", Prefix+"/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Enroll.GetJob(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, enrollReadError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/jobs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if _, err := d.Enroll.CancelJob(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", Prefix+"/jobs/{id}/retry", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Enroll.RetryJob(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, enrollError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
}
