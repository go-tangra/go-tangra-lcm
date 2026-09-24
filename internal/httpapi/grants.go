package httpapi

import (
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// GrantDeps are the services behind the permission and access routes.
type GrantDeps struct {
	Authz *authz.Authorizer
}

type grantBody struct {
	ResourceType string     `json:"resource_type"`
	ResourceID   string     `json:"resource_id"`
	SubjectType  string     `json:"subject_type"`
	SubjectID    string     `json:"subject_id"`
	Relation     string     `json:"relation"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

func grantView(g store.Grant) map[string]any {
	m := map[string]any{
		"id": g.ID, "resource_type": g.ResourceType, "resource_id": g.ResourceID,
		"subject_type": g.SubjectType, "subject_id": g.SubjectID, "relation": g.Relation,
		"granted_at": g.GrantedAt,
	}
	if g.GrantedBy != nil {
		m["granted_by"] = *g.GrantedBy
	}
	if g.ExpiresAt != nil {
		m["expires_at"] = *g.ExpiresAt
	}
	return m
}

// RegisterGrants mounts the permission and access routes (contracts §access).
func (s *Server) RegisterGrants(d GrantDeps) {
	s.MustHandle("GET", Prefix+"/grants", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		grants, err := d.Authz.ListGrants(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"))
		if err != nil {
			s.fail(w, r, readError(err))
			return
		}
		out := make([]map[string]any, 0, len(grants))
		for _, g := range grants {
			out = append(out, grantView(g))
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	})
	s.MustHandle("POST", Prefix+"/grants", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in grantBody
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, nil, err)
			return
		}
		g, err := d.Authz.Grant(r.Context(), subj, authz.GrantInput{ResourceType: in.ResourceType, ResourceID: in.ResourceID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Relation: in.Relation, ExpiresAt: in.ExpiresAt})
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, grantView(g))
	})
	s.MustHandle("POST", Prefix+"/grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Authz.Revoke(r.Context(), subj, r.PathValue("id")); err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", Prefix+"/access/check", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		err = d.Authz.Check(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"), q.Get("action"))
		allowed := err == nil
		if err != nil && err != authz.ErrForbidden && err != authz.ErrNotFound {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"allowed": allowed})
	})
	s.MustHandle("GET", Prefix+"/access/effective", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		perms, relation, grants, err := d.Authz.Effective(r.Context(), subj, q.Get("resource_type"), q.Get("resource_id"))
		if err != nil {
			s.fail(w, r, readError(err))
			return
		}
		gv := make([]map[string]any, 0, len(grants))
		for _, g := range grants {
			gv = append(gv, grantView(g))
		}
		WriteJSON(w, http.StatusOK, map[string]any{"relation": relation, "permissions": perms, "grants": gv})
	})
	s.MustHandle("GET", Prefix+"/access/accessible", func(w http.ResponseWriter, r *http.Request) {
		subj, err := subjects(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		ids, all, err := d.Authz.ListAccessibleIDs(r.Context(), subj, r.URL.Query().Get("resource_type"))
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"ids": list, "all": all})
	})
}
