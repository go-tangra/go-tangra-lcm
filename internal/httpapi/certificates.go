package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

type issueBody struct {
	IssuerID        string   `json:"issuer_id"`
	SpiffeID        string   `json:"spiffe_id"`
	CSRPEM          string   `json:"csr_pem"`
	Subject         string   `json:"subject"`
	DNSSans         []string `json:"dns_sans"`
	ValiditySeconds int64    `json:"validity_seconds"`
	DeliverKey      bool     `json:"deliver_key"`
}

// RegisterCertificates mounts the certificate routes (contracts §certificates).
func (s *Server) RegisterCertificates(d CertDeps) {
	s.MustHandle("GET", Prefix+"/certificates", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		f := store.CertificateFilter{IssuerID: q.Get("issuer_id"), SpiffeID: q.Get("spiffe_id"), Status: q.Get("status"), CursorID: q.Get("cursor"), Limit: limitParam(r)}
		items, next, err := d.Issue.ListCertificates(r.Context(), subj, f)
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
	})
	s.MustHandle("POST", Prefix+"/certificates/issue", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in issueBody
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		input := issue.IssueInput{IssuerID: in.IssuerID, SpiffeID: in.SpiffeID, CSRPEM: in.CSRPEM, Subject: in.Subject, DNSSans: in.DNSSans, ValiditySeconds: in.ValiditySeconds}
		// Issuance is asynchronous: validate synchronously (fast 400/403), then
		// background the mint and report the outcome over SSE (certificate.issued
		// | certificate.failed). A module-generated key is retained (sealed) so
		// the operator can download it from the certificate afterwards.
		if err := d.Issue.PrecheckIssue(r.Context(), subj, input); err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		input.RetainKey = true
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
			defer cancel()
			b, err := d.Issue.Issue(ctx, subj, input)
			if err != nil {
				if d.PubFail != nil {
					d.PubFail(ctx, subj.TenantID, map[string]any{"spiffe_id": in.SpiffeID, "error": issueFailMessage(err)})
				}
				return
			}
			publish(d, subj.TenantID, "issued", b.Certificate)
		}()
		WriteJSON(w, http.StatusAccepted, map[string]any{"status": "processing", "spiffe_id": in.SpiffeID})
	})
	s.MustHandle("POST", Prefix+"/certificates/acme", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			IssuerID   string   `json:"issuer_id"`
			Domains    []string `json:"domains"`
			CSRPEM     string   `json:"csr_pem"`
			DeliverKey bool     `json:"deliver_key"`
			AutoRenew  *bool    `json:"auto_renew"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		autoRenew := in.AutoRenew == nil || *in.AutoRenew // default on
		// ACME issuance (DNS-01) is slow, so run it asynchronously: validate
		// synchronously (fast 400/403), then background the order and report the
		// outcome over the SSE bus (certificate.issued | certificate.failed). The
		// generated key is retained and downloadable, so nothing is lost by not
		// returning a bundle inline.
		if err := d.Issue.PrecheckACME(r.Context(), subj, in.IssuerID); err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		domains := in.Domains
		csrPEM := in.CSRPEM
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 6*time.Minute)
			defer cancel()
			b, err := d.Issue.ObtainACME(ctx, subj, in.IssuerID, domains, csrPEM, false, autoRenew)
			if err != nil {
				if d.PubFail != nil {
					d.PubFail(ctx, subj.TenantID, map[string]any{"domains": domains, "error": issueFailMessage(err)})
				}
				return
			}
			publish(d, subj.TenantID, "issued", b.Certificate)
		}()
		WriteJSON(w, http.StatusAccepted, map[string]any{"status": "processing", "domains": domains})
	})
	s.MustHandle("GET", Prefix+"/certificates/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Issue.GetCertificate(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, issueReadError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", Prefix+"/certificates/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Owner     string `json:"owner"`
			AutoRenew *bool  `json:"auto_renew"`
		}
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Issue.UpdateCertificate(r.Context(), subj, r.PathValue("id"), issue.CertificateUpdate{Owner: in.Owner, AutoRenew: in.AutoRenew})
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("GET", Prefix+"/certificates/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		b, err := d.Issue.Download(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, issueReadError(err))
			return
		}
		WriteJSON(w, http.StatusOK, bundleJSON(b))
	})
	s.MustHandle("GET", Prefix+"/certificates/{id}/key", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		keyPEM, err := d.Issue.DownloadKey(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"key_pem": keyPEM})
	})
	s.MustHandle("POST", Prefix+"/certificates/{id}/renew", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		b, err := d.Issue.Renew(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		publish(d, subj.TenantID, "renewed", b.Certificate)
		WriteJSON(w, http.StatusOK, bundleJSON(b))
	})
	s.MustHandle("POST", Prefix+"/certificates/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		_ = DecodeJSON(r, &in, 0)
		cid := r.PathValue("id")
		if err := d.Issue.Revoke(r.Context(), subj, cid, in.Reason); err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		if d.Pub != nil {
			d.Pub(r.Context(), subj.TenantID, "revoked", cid, "", time.Time{})
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", Prefix+"/certificates/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Issue.DeleteCertificate(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// publish fans a certificate lifecycle event out to the tenant's live streams.
// issueFailMessage renders a short, client-safe reason for an async issuance
// failure. issue-layer errors (validation, and the acme package which already
// scrubs its own errors) carry no secrets; the length is capped defensively.
func issueFailMessage(err error) string {
	m := err.Error()
	if len(m) > 200 {
		m = m[:200]
	}
	return m
}

func publish(d CertDeps, tenantID, eventType string, c issue.CertificateView) {
	if d.Pub != nil {
		d.Pub(context.Background(), tenantID, eventType, c.ID, c.SpiffeID, c.NotAfter)
	}
}
