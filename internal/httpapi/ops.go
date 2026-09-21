package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/revoke"
	"github.com/go-freya/freya/services/lcm/internal/stats"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// AuditReader reads the audit trail (repo.Store satisfies it).
type AuditReader interface {
	QueryAudit(ctx context.Context, tenantID string, f store.AuditFilter) ([]store.AuditRow, error)
}

// OpsDeps are the services behind the operational routes.
type OpsDeps struct {
	Stats   *stats.Service
	Revoke  *revoke.Service
	Audit   AuditReader
	Version string
	Health  func(ctx context.Context) any
	// MeshTenantID keys the one mesh CA whose roots the public bootstrap-bundle
	// route serves (the cold-start trust anchor).
	MeshTenantID string
}

func auditView(r store.AuditRow) map[string]any {
	m := map[string]any{
		"ts": r.TS, "event_type": r.EventType, "actor_kind": r.ActorKind, "actor_id": r.ActorID,
		"subject_kind": r.SubjectKind, "subject_id": r.SubjectID, "outcome": r.Outcome,
	}
	if r.SubjectName != "" {
		m["subject_name"] = r.SubjectName
	}
	if r.Reason != "" {
		m["reason"] = r.Reason
	}
	if r.CorrelationID != "" {
		m["correlation_id"] = r.CorrelationID
	}
	if len(r.Details) > 0 {
		m["details"] = jsonRaw(r.Details)
	}
	return m
}

// RegisterOps mounts the statistics, audit, trust-bundle, revocation, CRL and
// health routes (contracts §operations).
func (s *Server) RegisterOps(d OpsDeps) {
	s.MustHandle("GET", Prefix+"/stats", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		v, err := d.Stats.Tenant(r.Context(), id.TenantID)
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("GET", Prefix+"/audit", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		q := r.URL.Query()
		f := store.AuditFilter{EventType: q.Get("event_type"), ActorID: q.Get("actor_id"), Limit: limitParam(r)}
		if v := q.Get("from"); v != "" {
			f.From, _ = time.Parse(time.RFC3339, v)
		}
		if v := q.Get("to"); v != "" {
			f.To, _ = time.Parse(time.RFC3339, v)
		}
		if v := q.Get("cursor"); v != "" {
			f.Cursor, _ = time.Parse(time.RFC3339Nano, v)
		}
		rows, err := d.Audit.QueryAudit(r.Context(), id.TenantID, f)
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		items := make([]map[string]any, 0, len(rows))
		var next string
		for _, row := range rows {
			items = append(items, auditView(row))
			next = row.TS.UTC().Format(time.RFC3339Nano)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
	})
	s.MustHandle("GET", Prefix+"/trust-bundle", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		pem, err := d.Revoke.TrustBundle(r.Context(), id.TenantID, r.URL.Query().Get("trust_domain"))
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"bundle_pem": pem})
	})
	s.MustHandle("GET", Prefix+"/bootstrap-bundle", func(w http.ResponseWriter, r *http.Request) {
		// Public: the mesh trust roots (public material, no secret) so a cold
		// workload can verify lcm's server cert before it enrolls.
		pem, err := d.Revoke.TrustBundle(r.Context(), d.MeshTenantID, r.URL.Query().Get("trust_domain"))
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"bundle_pem": pem})
	})
	s.MustHandle("GET", Prefix+"/revocations", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var cursor time.Time
		if c := r.URL.Query().Get("cursor"); c != "" {
			cursor, _ = time.Parse(time.RFC3339Nano, c)
		}
		items, err := d.Revoke.Feed(r.Context(), id.TenantID, cursor, limitParam(r))
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.MustHandle("GET", Prefix+"/crl", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		crl, err := d.Revoke.CRL(r.Context(), id.TenantID, r.URL.Query().Get("trust_domain"))
		if err != nil {
			s.fail(w, r, domainError(err))
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crl) // #nosec G705 -- DER/PEM CRL served as application/x-pem-file, never HTML
	})
	s.MustHandle("GET", Prefix+"/health", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"status": "ok", "version": d.Version}
		if d.Health != nil {
			out["health"] = d.Health(r.Context())
		}
		WriteJSON(w, http.StatusOK, out)
	})
}
