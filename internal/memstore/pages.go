package memstore

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// List-contract pages (go-tangra specs/032-server-side-tables): the same
// filters and visibility constraints as the SQL pages, sorted by the
// store.*List fields with the same semantics (listquery.SortSlice) and
// windowed with the total.

// window sorts items per req (completed with spec's defaults) and cuts the page.
func window[T any](items []T, spec listquery.Spec, req listquery.Request, key func(T, string) any, tie func(T) string) ([]T, int, listquery.Request) {
	req = store.ListRequest(req, spec)
	listquery.SortSlice(items, req, key, tie)
	page, total, applied := listquery.Window(items, req)
	if page == nil {
		page = []T{}
	}
	return page, total, applied
}

// visible mirrors the SQL visibility constraint (the zero value: nothing).
func visible(v store.Visible, id string) bool {
	return v.All || slices.Contains(v.IDs, id)
}

// firstSAN is the first entry of a JSON array of names ("" when none).
func firstSAN(raw []byte) string {
	var sans []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &sans)
	}
	if len(sans) == 0 {
		return ""
	}
	return sans[0]
}

// textOrNil is v, or nil (sorted last) when empty, like a NULL column.
func textOrNil(v string) any {
	if v == "" {
		return nil
	}
	return v
}

var spiffeShape = regexp.MustCompile(store.SpiffeShape)

// requestIssuerReadable mirrors store.requestIssuerReadable.
func requestIssuerReadable(s store.RequestScope, r store.CertificateRequest) bool {
	if r.IssuerID != nil && *r.IssuerID != "" {
		return s.AllPinned || slices.Contains(s.Issuers, *r.IssuerID)
	}
	if !spiffeShape.MatchString(r.SpiffeID) {
		return false
	}
	parts := strings.Split(r.SpiffeID, "/")
	return len(parts) >= 3 && slices.Contains(s.DefaultDomains, parts[2])
}

func (m *Mem) PageCertificates(_ context.Context, tid string, f store.CertificatePageFilter, req listquery.Request) ([]store.IssuedCertificate, int, listquery.Request, error) {
	if err := m.fail("PageCertificates"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.IssuedCertificate
	for _, c := range m.Certificates {
		if c.TenantID != tid || (f.IssuerID != "" && !strings.EqualFold(c.IssuerID, f.IssuerID)) || (f.SpiffeID != "" && c.SpiffeID != f.SpiffeID) ||
			(f.Status != "" && c.Status != f.Status) || !visible(f.Visible, c.ID) {
			continue
		}
		out = append(out, cpCertificate(c))
	}
	issuerName := func(id string) any {
		if i, ok := m.Issuers[id]; ok && i.TenantID == tid {
			return i.Name
		}
		return nil
	}
	spec := store.CertificateListFor(f.Visible)
	page, total, applied := window(out, spec, req, func(c store.IssuedCertificate, field string) any {
		switch field {
		case "identity":
			for _, v := range []string{c.SpiffeID, firstSAN(c.SANs), c.Subject} {
				if v != "" {
					return v
				}
			}
			return nil
		case "issuer":
			if !f.Visible.All {
				return c.IssuerID // store.CertificateListRestricted (F-3)
			}
			return issuerName(c.IssuerID)
		case "kind":
			return c.Kind
		case "status":
			return c.Status
		case "not_before":
			return c.NotBefore
		case "not_after":
			return c.NotAfter
		}
		return c.CreatedAt
	}, func(c store.IssuedCertificate) string { return c.ID })
	return page, total, applied, nil
}

func (m *Mem) PageIssuers(_ context.Context, tid string, v store.Visible, req listquery.Request) ([]store.Issuer, int, listquery.Request, error) {
	if err := m.fail("PageIssuers"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Issuer
	for _, i := range m.Issuers {
		if i.TenantID != tid || !visible(v, i.ID) {
			continue
		}
		c := cpIssuer(i)
		c.CertificateCount = m.certCountForIssuer(i.ID)
		out = append(out, c)
	}
	page, total, applied := window(out, store.IssuerList, req, func(i store.Issuer, field string) any {
		switch field {
		case "type":
			return i.Type
		case "trust_domain":
			return i.TrustDomain
		case "created_at":
			return i.CreatedAt
		}
		return i.Name
	}, func(i store.Issuer) string { return i.ID })
	return page, total, applied, nil
}

func (m *Mem) PageRequests(_ context.Context, tid, status string, s store.RequestScope, req listquery.Request) ([]store.CertificateRequest, int, listquery.Request, error) {
	if err := m.fail("PageRequests"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CertificateRequest
	for _, r := range m.Requests {
		if r.TenantID != tid || (status != "" && r.Status != status) {
			continue
		}
		if !(s.Actor != "" && r.RequestedBy == s.Actor) && !requestIssuerReadable(s, r) {
			continue
		}
		out = append(out, cpRequest(r))
	}
	page, total, applied := window(out, store.RequestList, req, func(r store.CertificateRequest, field string) any {
		switch field {
		case "identity":
			if r.SpiffeID != "" {
				return r.SpiffeID
			}
			return textOrNil(firstSAN(r.SANs))
		case "kind":
			return r.Kind
		case "status":
			return r.Status
		}
		return r.CreatedAt
	}, func(r store.CertificateRequest) string { return r.ID })
	return page, total, applied, nil
}

func (m *Mem) PageJobs(_ context.Context, tid, status string, s store.RequestScope, req listquery.Request) ([]store.CertificateJob, int, listquery.Request, error) {
	if err := m.fail("PageJobs"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CertificateJob
	for _, j := range m.Jobs {
		if j.TenantID != tid || (status != "" && j.Status != status) {
			continue
		}
		if !s.AllJobs {
			r, ok := m.Requests[j.RequestID]
			if !ok || r.TenantID != tid || !requestIssuerReadable(store.RequestScope{Issuers: s.Issuers, DefaultDomains: s.DefaultDomains}, r) {
				continue
			}
		}
		out = append(out, j)
	}
	page, total, applied := window(out, store.JobList, req, func(j store.CertificateJob, field string) any {
		switch field {
		case "type":
			return j.Type
		case "status":
			return j.Status
		case "attempts":
			return j.Attempts
		case "run_after":
			return j.RunAfter
		}
		return j.CreatedAt
	}, func(j store.CertificateJob) string { return j.ID })
	return page, total, applied, nil
}

func (m *Mem) PageSecrets(_ context.Context, tid string, req listquery.Request) ([]store.TenantSecret, int, listquery.Request, error) {
	if err := m.fail("PageSecrets"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.TenantSecret
	for _, s := range m.Secrets {
		if s.TenantID == tid {
			s.ValueSealed = nil // a listing never reads the sealed value
			out = append(out, s)
		}
	}
	page, total, applied := window(out, store.SecretList, req, func(s store.TenantSecret, field string) any {
		switch field {
		case "kind":
			return s.Kind
		case "created_at":
			return s.CreatedAt
		}
		return s.Name
	}, func(s store.TenantSecret) string { return s.ID })
	return page, total, applied, nil
}

func (m *Mem) PageWebhooks(_ context.Context, tid string, req listquery.Request) ([]store.WebhookEndpoint, int, listquery.Request, error) {
	if err := m.fail("PageWebhooks"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.WebhookEndpoint
	for _, w := range m.Webhooks {
		if w.TenantID == tid {
			out = append(out, cpWebhook(w))
		}
	}
	page, total, applied := window(out, store.WebhookList, req, func(w store.WebhookEndpoint, field string) any {
		if field == "created_at" {
			return w.CreatedAt
		}
		return w.Name
	}, func(w store.WebhookEndpoint) string { return w.ID })
	return page, total, applied, nil
}

func (m *Mem) PageAudit(_ context.Context, tid string, f store.AuditPageFilter, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error) {
	if err := m.fail("PageAudit"); err != nil {
		return nil, 0, req, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditRow
	for _, r := range m.Audit {
		if r.TenantID != tid || (f.EventType != "" && r.EventType != f.EventType) || (f.ActorID != "" && r.ActorID != f.ActorID) ||
			r.TS.Before(f.From) || r.TS.After(f.To) {
			continue
		}
		r = cpAudit(r)
		r.SubjectName = m.subjectName(tid, r)
		out = append(out, r)
	}
	page, total, applied := window(out, store.AuditList, req, func(r store.AuditRow, _ string) any { return r.TS },
		func(r store.AuditRow) string { return fmt.Sprintf("%020d", r.ID) })
	return page, total, applied, nil
}
