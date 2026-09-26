// Package memstore is the in-memory repo.Store double for unit tests. It
// applies the same tenant scoping, uniqueness and paging rules as the SQL
// repositories, deep-copies rows on the boundary, and supports failure
// injection per operation.
package memstore

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Mem holds every table; exported maps ease assertions in tests.
type Mem struct {
	mu           sync.Mutex
	Issuers      map[string]store.Issuer
	CAs          map[string]store.CA
	Requests     map[string]store.CertificateRequest
	Jobs         map[string]store.CertificateJob
	Certificates map[string]store.IssuedCertificate
	Revocations  map[string]store.Revocation
	Installed    map[string]store.InstalledCertificate
	Targets      map[string]store.DeploymentTarget
	Secrets      map[string]store.TenantSecret
	Webhooks     map[string]store.WebhookEndpoint
	Grants       map[string]store.Grant
	CertLog      []store.CertLogRow
	Audit        []store.AuditRow
	Fail         map[string]error // operation name → error to return
	Now          func() time.Time
}

// New returns an empty store.
func New() *Mem {
	return &Mem{
		Issuers:      map[string]store.Issuer{},
		CAs:          map[string]store.CA{},
		Requests:     map[string]store.CertificateRequest{},
		Jobs:         map[string]store.CertificateJob{},
		Certificates: map[string]store.IssuedCertificate{},
		Revocations:  map[string]store.Revocation{},
		Installed:    map[string]store.InstalledCertificate{},
		Targets:      map[string]store.DeploymentTarget{},
		Secrets:      map[string]store.TenantSecret{},
		Webhooks:     map[string]store.WebhookEndpoint{},
		Grants:       map[string]store.Grant{},
		Fail:         map[string]error{},
		Now:          time.Now,
	}
}

// FailOn makes op return err until cleared (err nil).
func (m *Mem) FailOn(op string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.Fail, op)
		return
	}
	m.Fail[op] = err
}

func (m *Mem) fail(op string) error { return m.Fail[op] }

// Atomic runs fn against the same store (no isolation in the double).
func (m *Mem) Atomic(_ context.Context, _ string, fn func(repo.Store) error) error {
	if err := m.fail("Atomic"); err != nil {
		return err
	}
	return fn(m)
}

// ---- helpers

func lower(s string) string { return strings.ToLower(s) }

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// beforeCursor reports whether (ts,id) sorts strictly before the descending
// cursor (cursorTS,cursorID); a zero cursor accepts everything.
func beforeCursor(ts time.Time, id string, cursorTS time.Time, cursorID string) bool {
	if cursorTS.IsZero() {
		return true
	}
	return ts.Before(cursorTS) || (ts.Equal(cursorTS) && id < cursorID)
}

func cpIssuer(i store.Issuer) store.Issuer {
	i.SettingsPublic = cloneBytes(i.SettingsPublic)
	i.SettingsSealed = cloneBytes(i.SettingsSealed)
	return i
}
func cpCA(c store.CA) store.CA { c.KeySealed = cloneBytes(c.KeySealed); return c }
func cpRequest(r store.CertificateRequest) store.CertificateRequest {
	r.SANs = cloneBytes(r.SANs)
	return r
}
func cpCertificate(c store.IssuedCertificate) store.IssuedCertificate {
	c.SANs = cloneBytes(c.SANs)
	c.KeySealed = cloneBytes(c.KeySealed)
	return c
}
func cpTarget(t store.DeploymentTarget) store.DeploymentTarget {
	t.ConfigPublic = cloneBytes(t.ConfigPublic)
	t.ConfigSealed = cloneBytes(t.ConfigSealed)
	return t
}
func cpSecret(s store.TenantSecret) store.TenantSecret {
	s.ValueSealed = cloneBytes(s.ValueSealed)
	return s
}
func cpWebhook(w store.WebhookEndpoint) store.WebhookEndpoint {
	w.EventTypes = cloneStrings(w.EventTypes)
	w.SecretSealed = cloneBytes(w.SecretSealed)
	if w.EventTypes == nil {
		w.EventTypes = []string{}
	}
	return w
}
func cpAudit(a store.AuditRow) store.AuditRow { a.Details = cloneBytes(a.Details); return a }

// ---- issuers

func (m *Mem) certCountForIssuer(id string) int {
	n := 0
	for _, c := range m.Certificates {
		if c.IssuerID == id {
			n++
		}
	}
	return n
}

func (m *Mem) InsertIssuer(_ context.Context, i store.Issuer) error {
	if err := m.fail("InsertIssuer"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if i.CAID != nil {
		if c, ok := m.CAs[*i.CAID]; !ok || c.TenantID != i.TenantID {
			return store.ErrConflict
		}
	}
	for _, x := range m.Issuers {
		if x.TenantID == i.TenantID && (lower(x.Name) == lower(i.Name) || (i.IsDefault && x.IsDefault && x.TrustDomain == i.TrustDomain)) {
			return store.ErrConflict
		}
	}
	now := m.Now()
	i.CreatedAt, i.UpdatedAt = now, now
	if i.SettingsPublic == nil {
		i.SettingsPublic = []byte("{}")
	}
	m.Issuers[i.ID] = cpIssuer(i)
	return nil
}

func (m *Mem) GetIssuer(_ context.Context, tid, id string) (store.Issuer, error) {
	if err := m.fail("GetIssuer"); err != nil {
		return store.Issuer{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.Issuers[id]
	if !ok || i.TenantID != tid {
		return store.Issuer{}, store.ErrNotFound
	}
	i = cpIssuer(i)
	i.CertificateCount = m.certCountForIssuer(id)
	return i, nil
}

func sortByNameID[T any](out []T, name func(T) string, id func(T) string) {
	sort.Slice(out, func(a, b int) bool {
		if lower(name(out[a])) != lower(name(out[b])) {
			return lower(name(out[a])) < lower(name(out[b]))
		}
		return id(out[a]) < id(out[b])
	})
}

func (m *Mem) ListIssuers(_ context.Context, tid, after string, limit int) ([]store.Issuer, error) {
	if err := m.fail("ListIssuers"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Issuer
	for _, i := range m.Issuers {
		if i.TenantID == tid && lower(i.Name) > lower(after) {
			c := cpIssuer(i)
			c.CertificateCount = m.certCountForIssuer(i.ID)
			out = append(out, c)
		}
	}
	sortByNameID(out, func(i store.Issuer) string { return i.Name }, func(i store.Issuer) string { return i.ID })
	out = sqlLimit(out, limit)
	return out, nil
}

func (m *Mem) IssuersByIDs(_ context.Context, tid string, ids []string) ([]store.Issuer, error) {
	if err := m.fail("IssuersByIDs"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Issuer
	for _, id := range ids {
		if i, ok := m.Issuers[id]; ok && i.TenantID == tid {
			c := cpIssuer(i)
			c.CertificateCount = m.certCountForIssuer(id)
			out = append(out, c)
		}
	}
	sortByNameID(out, func(i store.Issuer) string { return i.Name }, func(i store.Issuer) string { return i.ID })
	return out, nil
}

func (m *Mem) DefaultIssuer(_ context.Context, tid, trustDomain string) (store.Issuer, error) {
	if err := m.fail("DefaultIssuer"); err != nil {
		return store.Issuer{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.Issuers {
		if i.TenantID == tid && i.TrustDomain == trustDomain && i.IsDefault {
			c := cpIssuer(i)
			c.CertificateCount = m.certCountForIssuer(i.ID)
			return c, nil
		}
	}
	return store.Issuer{}, store.ErrNotFound
}

func (m *Mem) UpdateIssuer(_ context.Context, i store.Issuer) error {
	if err := m.fail("UpdateIssuer"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.Issuers[i.ID]
	if !ok || old.TenantID != i.TenantID {
		return store.ErrNotFound
	}
	if i.CAID != nil {
		if c, ok := m.CAs[*i.CAID]; !ok || c.TenantID != i.TenantID {
			return store.ErrConflict
		}
	}
	for id, x := range m.Issuers {
		if id != i.ID && x.TenantID == i.TenantID && (lower(x.Name) == lower(i.Name) || (i.IsDefault && x.IsDefault && x.TrustDomain == i.TrustDomain)) {
			return store.ErrConflict
		}
	}
	old.Name, old.Type, old.TrustDomain, old.IsDefault, old.CAID = i.Name, i.Type, i.TrustDomain, i.IsDefault, i.CAID
	old.ACMEDirectoryURL, old.ACMEEmail, old.DNSProvider = i.ACMEDirectoryURL, i.ACMEEmail, i.DNSProvider
	old.SettingsPublic, old.SettingsSealed, old.Enabled, old.UpdatedBy, old.UpdatedAt = i.SettingsPublic, i.SettingsSealed, i.Enabled, i.UpdatedBy, m.Now()
	m.Issuers[i.ID] = cpIssuer(old)
	return nil
}

func (m *Mem) ClearDefaultIssuer(_ context.Context, tid, trustDomain, except string) error {
	if err := m.fail("ClearDefaultIssuer"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, i := range m.Issuers {
		if i.TenantID == tid && i.TrustDomain == trustDomain && i.IsDefault && id != except {
			i.IsDefault = false
			m.Issuers[id] = i
		}
	}
	return nil
}

func (m *Mem) DeleteIssuer(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteIssuer"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.Issuers[id]
	if !ok || i.TenantID != tid {
		return store.ErrNotFound
	}
	if m.certCountForIssuer(id) > 0 {
		return store.ErrConflict
	}
	delete(m.Issuers, id)
	return nil
}

// ---- cas

func (m *Mem) InsertCA(_ context.Context, c store.CA) error {
	if err := m.fail("InsertCA"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.State == "active" {
		for _, x := range m.CAs {
			if x.TenantID == c.TenantID && x.TrustDomain == c.TrustDomain && x.State == "active" {
				return store.ErrConflict
			}
		}
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = m.Now()
	}
	m.CAs[c.ID] = cpCA(c)
	return nil
}

func (m *Mem) GetCA(_ context.Context, tid, id string) (store.CA, error) {
	if err := m.fail("GetCA"); err != nil {
		return store.CA{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.CAs[id]
	if !ok || c.TenantID != tid {
		return store.CA{}, store.ErrNotFound
	}
	return cpCA(c), nil
}

func (m *Mem) CAByState(_ context.Context, tid, trustDomain, state string) (store.CA, error) {
	if err := m.fail("CAByState"); err != nil {
		return store.CA{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *store.CA
	for _, c := range m.CAs {
		if c.TenantID == tid && c.TrustDomain == trustDomain && c.State == state {
			cc := c
			if best == nil || cc.CreatedAt.After(best.CreatedAt) {
				best = &cc
			}
		}
	}
	if best == nil {
		return store.CA{}, store.ErrNotFound
	}
	return cpCA(*best), nil
}

func (m *Mem) CAsForDomain(_ context.Context, tid, trustDomain string) ([]store.CA, error) {
	if err := m.fail("CAsForDomain"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CA
	for _, c := range m.CAs {
		if c.TenantID == tid && c.TrustDomain == trustDomain {
			out = append(out, cpCA(c))
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].CreatedAt.Equal(out[b].CreatedAt) {
			return out[a].CreatedAt.After(out[b].CreatedAt)
		}
		return out[a].ID > out[b].ID
	})
	return out, nil
}

func (m *Mem) SetCAState(_ context.Context, tid, id, state string) error {
	if err := m.fail("SetCAState"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.CAs[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	if state == "active" {
		for xid, x := range m.CAs {
			if xid != id && x.TenantID == tid && x.TrustDomain == c.TrustDomain && x.State == "active" {
				return store.ErrConflict
			}
		}
	}
	c.State = state
	m.CAs[id] = c
	return nil
}

func (m *Mem) DeleteCA(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteCA"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.CAs[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	for _, i := range m.Issuers {
		if i.CAID != nil && *i.CAID == id {
			return store.ErrConflict
		}
	}
	delete(m.CAs, id)
	return nil
}

// ---- certificate requests

func (m *Mem) InsertRequest(_ context.Context, r store.CertificateRequest) error {
	if err := m.fail("InsertRequest"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.IssuerID != nil {
		if i, ok := m.Issuers[*r.IssuerID]; !ok || i.TenantID != r.TenantID {
			return store.ErrConflict
		}
	}
	if r.Kind == "" {
		r.Kind = "svid"
	}
	now := m.Now()
	r.CreatedAt, r.UpdatedAt = now, now
	m.Requests[r.ID] = cpRequest(r)
	return nil
}

func (m *Mem) GetRequest(_ context.Context, tid, id string) (store.CertificateRequest, error) {
	if err := m.fail("GetRequest"); err != nil {
		return store.CertificateRequest{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || r.TenantID != tid {
		return store.CertificateRequest{}, store.ErrNotFound
	}
	return cpRequest(r), nil
}

// sqlLimit applies a page size like SQL LIMIT does: a limit <= 0 returns no
// rows (LIMIT 0; Postgres refuses a negative one), so a caller that forgets
// to default its page size fails here as it would against the database.
func sqlLimit[T any](out []T, limit int) []T {
	if limit <= 0 {
		return out[:0]
	}
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func sortDesc[T any](out []T, ts func(T) time.Time, id func(T) string) {
	sort.Slice(out, func(a, b int) bool {
		if !ts(out[a]).Equal(ts(out[b])) {
			return ts(out[a]).After(ts(out[b]))
		}
		return id(out[a]) > id(out[b])
	})
}

func (m *Mem) ListRequests(_ context.Context, tid string, f store.RequestFilter) ([]store.CertificateRequest, error) {
	if err := m.fail("ListRequests"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CertificateRequest
	for _, r := range m.Requests {
		if r.TenantID != tid || (f.Status != "" && r.Status != f.Status) {
			continue
		}
		if !beforeCursor(r.CreatedAt, r.ID, f.CursorTS, f.CursorID) {
			continue
		}
		out = append(out, cpRequest(r))
	}
	sortDesc(out, func(r store.CertificateRequest) time.Time { return r.CreatedAt }, func(r store.CertificateRequest) string { return r.ID })
	out = sqlLimit(out, f.Limit)
	return out, nil
}

func (m *Mem) SetRequestStatus(_ context.Context, tid, id, status string, approver, reason *string) error {
	if err := m.fail("SetRequestStatus"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || r.TenantID != tid {
		return store.ErrNotFound
	}
	r.Status = status
	if approver != nil {
		r.Approver = approver
	}
	if reason != nil {
		r.Reason = reason
	}
	r.UpdatedAt = m.Now()
	m.Requests[id] = r
	return nil
}

func (m *Mem) CompleteRequest(_ context.Context, tid, id, status string, certificateID, reason *string) error {
	if err := m.fail("CompleteRequest"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || r.TenantID != tid {
		return store.ErrNotFound
	}
	r.Status, r.CertificateID, r.Reason = status, certificateID, reason
	r.UpdatedAt = m.Now()
	m.Requests[id] = r
	return nil
}

func (m *Mem) DeleteRequest(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteRequest"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || r.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Requests, id)
	return nil
}

// ---- certificate jobs

func (m *Mem) InsertJob(_ context.Context, j store.CertificateJob) error {
	if err := m.fail("InsertJob"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	j.CreatedAt, j.UpdatedAt = now, now
	if j.RunAfter.IsZero() {
		j.RunAfter = now
	}
	m.Jobs[j.ID] = j
	return nil
}

func (m *Mem) GetJob(_ context.Context, tid, id string) (store.CertificateJob, error) {
	if err := m.fail("GetJob"); err != nil {
		return store.CertificateJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.Jobs[id]
	if !ok || j.TenantID != tid {
		return store.CertificateJob{}, store.ErrNotFound
	}
	return j, nil
}

func (m *Mem) ListJobs(_ context.Context, tid string, f store.JobFilter) ([]store.CertificateJob, error) {
	if err := m.fail("ListJobs"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CertificateJob
	for _, j := range m.Jobs {
		if j.TenantID != tid || (f.Status != "" && j.Status != f.Status) {
			continue
		}
		if !beforeCursor(j.CreatedAt, j.ID, f.CursorTS, f.CursorID) {
			continue
		}
		out = append(out, j)
	}
	sortDesc(out, func(j store.CertificateJob) time.Time { return j.CreatedAt }, func(j store.CertificateJob) string { return j.ID })
	out = sqlLimit(out, f.Limit)
	return out, nil
}

func (m *Mem) UpdateJob(_ context.Context, j store.CertificateJob) error {
	if err := m.fail("UpdateJob"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.Jobs[j.ID]
	if !ok || old.TenantID != j.TenantID {
		return store.ErrNotFound
	}
	old.Status, old.LeaseUntil, old.Attempts, old.MaxAttempts = j.Status, j.LeaseUntil, j.Attempts, j.MaxAttempts
	old.ResultCertificateID, old.Error, old.RunAfter, old.UpdatedAt = j.ResultCertificateID, j.Error, j.RunAfter, m.Now()
	m.Jobs[j.ID] = old
	return nil
}

func (m *Mem) DeleteJob(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteJob"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.Jobs[id]
	if !ok || j.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Jobs, id)
	return nil
}

func (m *Mem) ClaimDueJobs(_ context.Context, now time.Time, lease time.Duration, limit int) ([]store.CertificateJob, error) {
	if err := m.fail("ClaimDueJobs"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []store.CertificateJob
	for _, j := range m.Jobs {
		if j.Status == "queued" && !j.RunAfter.After(now) && (j.LeaseUntil == nil || j.LeaseUntil.Before(now)) {
			due = append(due, j)
		}
	}
	sort.Slice(due, func(a, b int) bool {
		if !due[a].RunAfter.Equal(due[b].RunAfter) {
			return due[a].RunAfter.Before(due[b].RunAfter)
		}
		return due[a].ID < due[b].ID
	})
	due = sqlLimit(due, limit)
	until := now.Add(lease)
	out := make([]store.CertificateJob, 0, len(due))
	for _, j := range due {
		stored := m.Jobs[j.ID]
		stored.Status, stored.LeaseUntil, stored.Attempts, stored.UpdatedAt = "processing", &until, stored.Attempts+1, now
		m.Jobs[j.ID] = stored
		out = append(out, stored)
	}
	return out, nil
}

// ---- issued certificates

func (m *Mem) InsertCertificate(_ context.Context, c store.IssuedCertificate) error {
	if err := m.fail("InsertCertificate"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if i, ok := m.Issuers[c.IssuerID]; !ok || i.TenantID != c.TenantID {
		return store.ErrConflict
	}
	for _, x := range m.Certificates {
		if x.TenantID == c.TenantID && x.Serial == c.Serial {
			return store.ErrConflict
		}
	}
	now := m.Now()
	c.CreatedAt, c.UpdatedAt = now, now
	if c.SANs == nil {
		c.SANs = []byte("[]")
	}
	m.Certificates[c.ID] = cpCertificate(c)
	return nil
}

func (m *Mem) GetCertificate(_ context.Context, tid, id string) (store.IssuedCertificate, error) {
	if err := m.fail("GetCertificate"); err != nil {
		return store.IssuedCertificate{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Certificates[id]
	if !ok || c.TenantID != tid {
		return store.IssuedCertificate{}, store.ErrNotFound
	}
	return cpCertificate(c), nil
}

func (m *Mem) ListCertificates(_ context.Context, tid string, f store.CertificateFilter) ([]store.IssuedCertificate, error) {
	if err := m.fail("ListCertificates"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.IssuedCertificate
	for _, c := range m.Certificates {
		if c.TenantID != tid || (f.IssuerID != "" && c.IssuerID != f.IssuerID) || (f.SpiffeID != "" && c.SpiffeID != f.SpiffeID) || (f.Status != "" && c.Status != f.Status) {
			continue
		}
		if !beforeCursor(c.CreatedAt, c.ID, f.CursorTS, f.CursorID) {
			continue
		}
		out = append(out, cpCertificate(c))
	}
	sortDesc(out, func(c store.IssuedCertificate) time.Time { return c.CreatedAt }, func(c store.IssuedCertificate) string { return c.ID })
	out = sqlLimit(out, f.Limit)
	return out, nil
}

func (m *Mem) CertificatesByIDs(_ context.Context, tid string, ids []string) ([]store.IssuedCertificate, error) {
	if err := m.fail("CertificatesByIDs"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.IssuedCertificate
	for _, id := range ids {
		if c, ok := m.Certificates[id]; ok && c.TenantID == tid {
			out = append(out, cpCertificate(c))
		}
	}
	sortDesc(out, func(c store.IssuedCertificate) time.Time { return c.CreatedAt }, func(c store.IssuedCertificate) string { return c.ID })
	return out, nil
}

func (m *Mem) UpdateCertificate(_ context.Context, c store.IssuedCertificate) error {
	if err := m.fail("UpdateCertificate"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.Certificates[c.ID]
	if !ok || old.TenantID != c.TenantID {
		return store.ErrNotFound
	}
	old.Status, old.ChainPEM, old.KeySealed, old.KeyDelivered = c.Status, c.ChainPEM, c.KeySealed, c.KeyDelivered
	old.SupersededBy, old.Owner, old.UpdatedBy, old.UpdatedAt = c.SupersededBy, c.Owner, c.UpdatedBy, m.Now()
	m.Certificates[c.ID] = cpCertificate(old)
	return nil
}

func (m *Mem) SetCertificateStatus(_ context.Context, tid, id, status string, supersededBy *string) error {
	if err := m.fail("SetCertificateStatus"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Certificates[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	c.Status = status
	if supersededBy != nil {
		c.SupersededBy = supersededBy
	}
	c.UpdatedAt = m.Now()
	m.Certificates[id] = c
	return nil
}

func (m *Mem) MarkKeyDelivered(_ context.Context, tid, id string) error {
	if err := m.fail("MarkKeyDelivered"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Certificates[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	c.KeyDelivered, c.KeySealed, c.UpdatedAt = true, nil, m.Now()
	m.Certificates[id] = c
	return nil
}

func (m *Mem) DeleteCertificate(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteCertificate"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Certificates[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Certificates, id)
	return nil
}

func (m *Mem) DueForRenewal(_ context.Context, now, notAfterBefore time.Time, limit int) ([]store.IssuedCertificate, error) {
	if err := m.fail("DueForRenewal"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.IssuedCertificate
	for _, c := range m.Certificates {
		if (c.Status == "active" || c.Status == "expiring") && c.SupersededBy == nil && c.NotAfter.After(now) && !c.NotAfter.After(notAfterBefore) {
			out = append(out, cpCertificate(c))
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].NotAfter.Equal(out[b].NotAfter) {
			return out[a].NotAfter.Before(out[b].NotAfter)
		}
		return out[a].ID < out[b].ID
	})
	out = sqlLimit(out, limit)
	return out, nil
}

// ---- revocations

func (m *Mem) InsertRevocation(_ context.Context, r store.Revocation) error {
	if err := m.fail("InsertRevocation"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Revocations {
		if x.TenantID == r.TenantID && x.CertificateID == r.CertificateID {
			return store.ErrConflict
		}
	}
	if r.RevokedAt.IsZero() {
		r.RevokedAt = m.Now()
	}
	m.Revocations[r.ID] = r
	return nil
}

func (m *Mem) ListRevocations(_ context.Context, tid string, cursor time.Time, limit int) ([]store.Revocation, error) {
	if err := m.fail("ListRevocations"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Revocation
	for _, r := range m.Revocations {
		if r.TenantID != tid || (!cursor.IsZero() && !r.RevokedAt.Before(cursor)) {
			continue
		}
		out = append(out, r)
	}
	sortDesc(out, func(r store.Revocation) time.Time { return r.RevokedAt }, func(r store.Revocation) string { return r.ID })
	out = sqlLimit(out, limit)
	return out, nil
}

// ---- installed certificates

func (m *Mem) UpsertInstalled(_ context.Context, i store.InstalledCertificate) error {
	if err := m.fail("UpsertInstalled"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, x := range m.Installed {
		if x.TenantID == i.TenantID && x.CertificateID == i.CertificateID && x.ClientID == i.ClientID {
			x.ReportedAt = i.ReportedAt
			m.Installed[id] = x
			return nil
		}
	}
	if i.InstalledAt.IsZero() {
		i.InstalledAt = m.Now()
	}
	if i.ReportedAt.IsZero() {
		i.ReportedAt = m.Now()
	}
	m.Installed[i.ID] = i
	return nil
}

func (m *Mem) ListInstalled(_ context.Context, tid, clientID string, cursor time.Time, limit int) ([]store.InstalledCertificate, error) {
	if err := m.fail("ListInstalled"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.InstalledCertificate
	for _, i := range m.Installed {
		if i.TenantID != tid || (clientID != "" && i.ClientID != clientID) || (!cursor.IsZero() && !i.ReportedAt.Before(cursor)) {
			continue
		}
		out = append(out, i)
	}
	sortDesc(out, func(i store.InstalledCertificate) time.Time { return i.ReportedAt }, func(i store.InstalledCertificate) string { return i.ID })
	out = sqlLimit(out, limit)
	return out, nil
}

// ---- deployment targets

func (m *Mem) InsertTarget(_ context.Context, t store.DeploymentTarget) error {
	if err := m.fail("InsertTarget"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Targets {
		if x.TenantID == t.TenantID && lower(x.Name) == lower(t.Name) {
			return store.ErrConflict
		}
	}
	now := m.Now()
	t.CreatedAt, t.UpdatedAt = now, now
	if t.ConfigPublic == nil {
		t.ConfigPublic = []byte("{}")
	}
	m.Targets[t.ID] = cpTarget(t)
	return nil
}

func (m *Mem) GetTarget(_ context.Context, tid, id string) (store.DeploymentTarget, error) {
	if err := m.fail("GetTarget"); err != nil {
		return store.DeploymentTarget{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Targets[id]
	if !ok || t.TenantID != tid {
		return store.DeploymentTarget{}, store.ErrNotFound
	}
	return cpTarget(t), nil
}

func (m *Mem) ListTargets(_ context.Context, tid string) ([]store.DeploymentTarget, error) {
	if err := m.fail("ListTargets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.DeploymentTarget
	for _, t := range m.Targets {
		if t.TenantID == tid {
			out = append(out, cpTarget(t))
		}
	}
	sortByNameID(out, func(t store.DeploymentTarget) string { return t.Name }, func(t store.DeploymentTarget) string { return t.ID })
	return out, nil
}

func (m *Mem) DeleteTarget(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteTarget"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Targets[id]
	if !ok || t.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Targets, id)
	return nil
}

// ---- tenant secrets

func (m *Mem) InsertSecret(_ context.Context, s store.TenantSecret) error {
	if err := m.fail("InsertSecret"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Secrets {
		if x.TenantID == s.TenantID && lower(x.Name) == lower(s.Name) {
			return store.ErrConflict
		}
	}
	now := m.Now()
	s.CreatedAt, s.UpdatedAt = now, now
	m.Secrets[s.ID] = cpSecret(s)
	return nil
}

func (m *Mem) GetSecret(_ context.Context, tid, id string) (store.TenantSecret, error) {
	if err := m.fail("GetSecret"); err != nil {
		return store.TenantSecret{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Secrets[id]
	if !ok || s.TenantID != tid {
		return store.TenantSecret{}, store.ErrNotFound
	}
	return cpSecret(s), nil
}

func (m *Mem) SecretByName(_ context.Context, tid, name string) (store.TenantSecret, error) {
	if err := m.fail("SecretByName"); err != nil {
		return store.TenantSecret{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.Secrets {
		if s.TenantID == tid && lower(s.Name) == lower(name) {
			return cpSecret(s), nil
		}
	}
	return store.TenantSecret{}, store.ErrNotFound
}

func (m *Mem) ListSecrets(_ context.Context, tid string) ([]store.TenantSecret, error) {
	if err := m.fail("ListSecrets"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.TenantSecret
	for _, s := range m.Secrets {
		if s.TenantID == tid {
			out = append(out, cpSecret(s))
		}
	}
	sortByNameID(out, func(s store.TenantSecret) string { return s.Name }, func(s store.TenantSecret) string { return s.ID })
	return out, nil
}

func (m *Mem) UpdateSecret(_ context.Context, s store.TenantSecret) error {
	if err := m.fail("UpdateSecret"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.Secrets[s.ID]
	if !ok || old.TenantID != s.TenantID {
		return store.ErrNotFound
	}
	for id, x := range m.Secrets {
		if id != s.ID && x.TenantID == s.TenantID && lower(x.Name) == lower(s.Name) {
			return store.ErrConflict
		}
	}
	old.Name, old.Kind, old.ValueSealed, old.UpdatedBy, old.UpdatedAt = s.Name, s.Kind, s.ValueSealed, s.UpdatedBy, m.Now()
	m.Secrets[s.ID] = cpSecret(old)
	return nil
}

func (m *Mem) DeleteSecret(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteSecret"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Secrets[id]
	if !ok || s.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Secrets, id)
	return nil
}

// ---- webhook endpoints

func (m *Mem) InsertWebhook(_ context.Context, w store.WebhookEndpoint) error {
	if err := m.fail("InsertWebhook"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Webhooks {
		if x.TenantID == w.TenantID && lower(x.Name) == lower(w.Name) {
			return store.ErrConflict
		}
	}
	now := m.Now()
	w.CreatedAt, w.UpdatedAt = now, now
	if w.EventTypes == nil {
		w.EventTypes = []string{}
	}
	m.Webhooks[w.ID] = cpWebhook(w)
	return nil
}

func (m *Mem) GetWebhook(_ context.Context, tid, id string) (store.WebhookEndpoint, error) {
	if err := m.fail("GetWebhook"); err != nil {
		return store.WebhookEndpoint{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.Webhooks[id]
	if !ok || w.TenantID != tid {
		return store.WebhookEndpoint{}, store.ErrNotFound
	}
	return cpWebhook(w), nil
}

func (m *Mem) ListWebhooks(_ context.Context, tid string) ([]store.WebhookEndpoint, error) {
	if err := m.fail("ListWebhooks"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.WebhookEndpoint
	for _, w := range m.Webhooks {
		if w.TenantID == tid {
			out = append(out, cpWebhook(w))
		}
	}
	sortByNameID(out, func(w store.WebhookEndpoint) string { return w.Name }, func(w store.WebhookEndpoint) string { return w.ID })
	return out, nil
}

func (m *Mem) WebhooksForEvent(_ context.Context, tid, eventType string) ([]store.WebhookEndpoint, error) {
	if err := m.fail("WebhooksForEvent"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.WebhookEndpoint
	for _, w := range m.Webhooks {
		if w.TenantID == tid && w.Enabled && contains(w.EventTypes, eventType) {
			out = append(out, cpWebhook(w))
		}
	}
	sortByNameID(out, func(w store.WebhookEndpoint) string { return w.Name }, func(w store.WebhookEndpoint) string { return w.ID })
	return out, nil
}

func (m *Mem) DeleteWebhook(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteWebhook"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.Webhooks[id]
	if !ok || w.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Webhooks, id)
	return nil
}

// ---- grants

func (m *Mem) UpsertGrant(_ context.Context, g store.Grant) (store.Grant, error) {
	if err := m.fail("UpsertGrant"); err != nil {
		return store.Grant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, x := range m.Grants {
		if x.TenantID == g.TenantID && x.ResourceType == g.ResourceType && x.ResourceID == g.ResourceID && x.SubjectType == g.SubjectType && x.SubjectID == g.SubjectID {
			x.Relation, x.GrantedBy, x.GrantedAt, x.ExpiresAt = g.Relation, g.GrantedBy, m.Now(), g.ExpiresAt
			m.Grants[id] = x
			return x, nil
		}
	}
	g.GrantedAt = m.Now()
	m.Grants[g.ID] = g
	return g, nil
}

func (m *Mem) GetGrant(_ context.Context, tid, id string) (store.Grant, error) {
	if err := m.fail("GetGrant"); err != nil {
		return store.Grant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.Grants[id]
	if !ok || g.TenantID != tid {
		return store.Grant{}, store.ErrNotFound
	}
	return g, nil
}

func (m *Mem) DeleteGrant(_ context.Context, tid, id string) error {
	if err := m.fail("DeleteGrant"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.Grants[id]
	if !ok || g.TenantID != tid {
		return store.ErrNotFound
	}
	delete(m.Grants, id)
	return nil
}

func sortGrants(out []store.Grant) {
	sort.Slice(out, func(i, j int) bool {
		if !out[i].GrantedAt.Equal(out[j].GrantedAt) {
			return out[i].GrantedAt.Before(out[j].GrantedAt)
		}
		return out[i].ID < out[j].ID
	})
}

func (m *Mem) GrantsOnResource(_ context.Context, tid, rt, rid string) ([]store.Grant, error) {
	if err := m.fail("GrantsOnResource"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Grant
	for _, g := range m.Grants {
		if g.TenantID == tid && g.ResourceType == rt && g.ResourceID == rid {
			out = append(out, g)
		}
	}
	sortGrants(out)
	return out, nil
}

func (m *Mem) GrantsForSubjects(_ context.Context, tid, uid string, roles []string, now time.Time) ([]store.Grant, error) {
	if err := m.fail("GrantsForSubjects"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Grant
	for _, g := range m.Grants {
		if g.TenantID != tid || (g.ExpiresAt != nil && !g.ExpiresAt.After(now)) {
			continue
		}
		switch g.SubjectType {
		case "user":
			if uid == "" || g.SubjectID != uid {
				continue
			}
		case "role":
			if !contains(roles, g.SubjectID) {
				continue
			}
		case "tenant":
			// tenant-wide grants always apply
		default:
			continue
		}
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

func (m *Mem) DeleteGrantsOfResource(_ context.Context, tid, rt, rid string) error {
	if err := m.fail("DeleteGrantsOfResource"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, g := range m.Grants {
		if g.TenantID == tid && g.ResourceType == rt && g.ResourceID == rid {
			delete(m.Grants, id)
		}
	}
	return nil
}

// ---- certificate log

func (m *Mem) InsertCertLog(_ context.Context, rows []store.CertLogRow) error {
	if err := m.fail("InsertCertLog"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CertLog = append(m.CertLog, rows...)
	return nil
}

// ---- audit & stats

func (m *Mem) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	if err := m.fail("InsertAuditRows"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.Audit = append(m.Audit, cpAudit(r))
	}
	return nil
}

func (m *Mem) QueryAudit(_ context.Context, tid string, f store.AuditFilter) ([]store.AuditRow, error) {
	if err := m.fail("QueryAudit"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditRow
	for _, r := range m.Audit {
		if r.TenantID != tid || (f.EventType != "" && r.EventType != f.EventType) || (f.ActorID != "" && r.ActorID != f.ActorID) ||
			(!f.From.IsZero() && r.TS.Before(f.From)) || (!f.To.IsZero() && r.TS.After(f.To)) || (!f.Cursor.IsZero() && !r.TS.Before(f.Cursor)) {
			continue
		}
		r = cpAudit(r)
		switch r.SubjectKind {
		case "issuer":
			if x, ok := m.Issuers[r.SubjectID]; ok && x.TenantID == tid {
				r.SubjectName = x.Name
			}
		case "certificate":
			if x, ok := m.Certificates[r.SubjectID]; ok && x.TenantID == tid {
				r.SubjectName = x.SpiffeID
			}
		case "secret":
			if x, ok := m.Secrets[r.SubjectID]; ok && x.TenantID == tid {
				r.SubjectName = x.Name
			}
		case "webhook":
			if x, ok := m.Webhooks[r.SubjectID]; ok && x.TenantID == tid {
				r.SubjectName = x.Name
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	if limit := store.AuditLimit(f.Limit); len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Mem) TenantStats(_ context.Context, tid string, now time.Time, window time.Duration) (store.Stats, error) {
	if err := m.fail("TenantStats"); err != nil {
		return store.Stats{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := store.Stats{Certificates: map[string]int64{}, Jobs: map[string]int64{}}
	since := now.Add(-window)
	expBefore := now.Add(window)
	for _, i := range m.Issuers {
		if i.TenantID == tid {
			st.Issuers++
		}
	}
	clients := map[string]struct{}{}
	for _, ic := range m.Installed {
		if ic.TenantID == tid {
			clients[ic.ClientID] = struct{}{}
		}
	}
	st.Clients = int64(len(clients))
	for _, c := range m.Certificates {
		if c.TenantID != tid {
			continue
		}
		st.Certificates[c.Status]++
		if (c.Status == "active" || c.Status == "expiring") && c.NotAfter.After(now) && !c.NotAfter.After(expBefore) {
			st.ExpiringSoon++
		}
	}
	for _, j := range m.Jobs {
		if j.TenantID == tid {
			st.Jobs[j.Status]++
		}
	}
	for _, l := range m.CertLog {
		if l.TenantID == tid && l.Event == "failed" && !l.TS.Before(since) {
			st.RecentErrors++
		}
	}
	for _, a := range m.Audit {
		if a.TenantID == tid && !a.TS.Before(since) {
			st.Operations24h++
		}
	}
	return st, nil
}

var _ repo.Store = (*Mem)(nil)
