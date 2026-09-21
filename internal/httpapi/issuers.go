package httpapi

import (
	"net/http"
	"strings"

	"github.com/go-freya/freya/services/lcm/internal/acme"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
)

type issuerBody struct {
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	TrustDomain      string          `json:"trust_domain"`
	IsDefault        bool            `json:"is_default"`
	Enabled          bool            `json:"enabled"`
	ACMEDirectoryURL string          `json:"acme_directory_url"`
	ACMEEmail        string          `json:"acme_email"`
	DNSProvider      string          `json:"dns_provider"`
	Settings         sealed.Settings `json:"settings"`
	Secrets          sealed.Settings `json:"secrets"`
}

func (b issuerBody) input() issue.IssuerInput {
	s := sealed.Settings{}
	for k, v := range b.Settings {
		s[k] = v
	}
	for k, v := range b.Secrets {
		s[k] = v
	}
	// The UI carries the ACME directory/email/DNS provider inside `settings`
	// (directory/email/dns_provider); the service reads them from the top-level
	// input fields. Promote the nested values when the top-level ones are empty
	// so either shape produces a working ACME issuer.
	dir := firstNonEmpty(b.ACMEDirectoryURL, settingString(s, "directory"))
	email := firstNonEmpty(b.ACMEEmail, settingString(s, "email"))
	dnsProv := firstNonEmpty(b.DNSProvider, settingString(s, "dns_provider"))
	return issue.IssuerInput{
		Name: b.Name, Type: b.Type, TrustDomain: strings.TrimSpace(b.TrustDomain), IsDefault: b.IsDefault,
		Enabled: b.Enabled, ACMEDirectoryURL: strings.TrimSpace(dir), ACMEEmail: strings.TrimSpace(email),
		DNSProvider: dnsProv, Settings: s,
	}
}

func settingString(s sealed.Settings, key string) string {
	if v, ok := s[key]; ok {
		if str, ok := v.(string); ok {
			return str
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// RegisterIssuers mounts the issuer routes (contracts §issuers).
func (s *Server) RegisterIssuers(d CertDeps) {
	s.MustHandle("GET", Prefix+"/issuers", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		items, next, err := d.Issue.ListIssuers(r.Context(), subj, r.URL.Query().Get("cursor"), limitParam(r))
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
	})
	s.MustHandle("POST", Prefix+"/issuers", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in issuerBody
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Issue.CreateIssuer(r.Context(), subj, in.input())
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("GET", Prefix+"/issuers/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Issue.GetIssuer(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.fail(w, r, issueReadError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("PUT", Prefix+"/issuers/{id}", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in issuerBody
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Issue.UpdateIssuer(r.Context(), subj, r.PathValue("id"), in.input())
		if err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("POST", Prefix+"/issuers/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Issue.DeleteIssuer(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, issueError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// DNS providers the ACME issuers can solve DNS-01 with (US4).
	s.MustHandle("GET", Prefix+"/dns-providers", func(w http.ResponseWriter, r *http.Request) {
		if _, err := subjects(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": acme.Providers()})
	})
}
