package issue

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/repo"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// CertificateView is an issued certificate as returned to clients. It carries
// no key material; Status is derived at read time and is never written back.
type CertificateView struct {
	ID                string            `json:"id"`
	IssuerID          string            `json:"issuer_id"`
	Kind              string            `json:"kind"`
	Serial            string            `json:"serial"`
	SpiffeID          string            `json:"spiffe_id"`
	Subject           string            `json:"subject"`
	SANs              []string          `json:"sans"`
	NotBefore         time.Time         `json:"not_before"`
	NotAfter          time.Time         `json:"not_after"`
	FingerprintSHA256 string            `json:"fingerprint_sha256"`
	Status            string            `json:"status"`
	KeyDelivered      bool              `json:"key_delivered"`
	HasKey            bool              `json:"has_key"`
	AutoRenew         bool              `json:"auto_renew"`
	SupersededBy      string            `json:"superseded_by,omitempty"`
	Owner             string            `json:"owner"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Permissions       authz.Permissions `json:"permissions"`
}

// CertificateUpdate carries the mutable metadata of a certificate. Owner is the
// only persisted field (the row has no label column); it is applied when set.
type CertificateUpdate struct {
	Owner     string
	AutoRenew *bool
}

// deriveStatus computes the effective status at now without mutating the row: a
// revoked certificate stays revoked; past not_after is expired; within
// min(30d, 0.5*TTL) of not_after is expiring; otherwise active.
func deriveStatus(c store.IssuedCertificate, now time.Time) string {
	if c.Status == "revoked" {
		return "revoked"
	}
	if !now.Before(c.NotAfter) {
		return "expired"
	}
	window := expiringWindow
	if half := c.NotAfter.Sub(c.NotBefore) / 2; half < window {
		window = half
	}
	if !c.NotAfter.After(now.Add(window)) {
		return "expiring"
	}
	return "active"
}

// certView projects a row with the derived status and the caller's permissions.
func (s *Service) certView(c store.IssuedCertificate, p authz.Permissions) CertificateView {
	var sans []string
	if len(c.SANs) > 0 {
		_ = json.Unmarshal(c.SANs, &sans)
	}
	return CertificateView{
		ID: c.ID, IssuerID: c.IssuerID, Kind: c.Kind, Serial: c.Serial, SpiffeID: c.SpiffeID, Subject: c.Subject,
		SANs: sans, NotBefore: c.NotBefore, NotAfter: c.NotAfter, FingerprintSHA256: c.FingerprintSHA256,
		Status: deriveStatus(c, s.now()), KeyDelivered: c.KeyDelivered, HasKey: len(c.KeySealed) > 0, AutoRenew: c.AutoRenew, SupersededBy: strp(c.SupersededBy),
		Owner: c.Owner, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, Permissions: p,
	}
}

// GetCertificate returns a certificate the caller may read.
func (s *Service) GetCertificate(ctx context.Context, subj authz.Subjects, id string) (CertificateView, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, id, authz.Read); err != nil {
		return CertificateView{}, err
	}
	row, err := s.st.GetCertificate(ctx, subj.TenantID, id)
	if err != nil {
		return CertificateView{}, err
	}
	perms, _, _, err := s.az.Effective(ctx, subj, authz.Certificate, id)
	if err != nil {
		return CertificateView{}, err
	}
	return s.certView(row, perms), nil
}

// ListCertificates returns the certificates the caller may read matching the
// filter, plus the next cursor (the last row's id) when the page is full.
func (s *Service) ListCertificates(ctx context.Context, subj authz.Subjects, f store.CertificateFilter) ([]CertificateView, string, error) {
	ids, all, err := s.az.ListAccessibleIDs(ctx, subj, authz.Certificate)
	if err != nil {
		return nil, "", err
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 50
	}
	out := []CertificateView{}
	next := ""
	for len(out) < f.Limit {
		rows, lerr := s.st.ListCertificates(ctx, subj.TenantID, f)
		if lerr != nil {
			return nil, "", lerr
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			f.CursorTS, f.CursorID = row.CreatedAt, row.ID
			if !all && !ids[row.ID] {
				continue
			}
			perms, _, _, perr := s.az.Effective(ctx, subj, authz.Certificate, row.ID)
			if perr != nil {
				return nil, "", perr
			}
			out = append(out, s.certView(row, perms))
			if len(out) == f.Limit {
				break
			}
		}
		if len(rows) < f.Limit {
			break
		}
	}
	if len(out) == f.Limit {
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// UpdateCertificate applies mutable metadata (owner) to a certificate the caller
// may write.
func (s *Service) UpdateCertificate(ctx context.Context, subj authz.Subjects, id string, in CertificateUpdate) (CertificateView, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, id, authz.Write); err != nil {
		return CertificateView{}, err
	}
	row, err := s.st.GetCertificate(ctx, subj.TenantID, id)
	if err != nil {
		return CertificateView{}, err
	}
	if in.Owner != "" {
		row.Owner = in.Owner
	}
	if in.AutoRenew != nil {
		row.AutoRenew = *in.AutoRenew
	}
	row.UpdatedBy = userPtr(subj)
	if err := s.st.UpdateCertificate(ctx, row); err != nil {
		return CertificateView{}, err
	}
	return s.GetCertificate(ctx, subj, id)
}

// DeleteCertificate removes a certificate the caller may delete and drops its
// grants.
func (s *Service) DeleteCertificate(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.az.Check(ctx, subj, authz.Certificate, id, authz.Delete); err != nil {
		return err
	}
	row, err := s.st.GetCertificate(ctx, subj.TenantID, id)
	if err != nil {
		return err
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if derr := tx.DeleteCertificate(ctx, subj.TenantID, id); derr != nil {
			return derr
		}
		return authz.New(tx).DropResource(ctx, subj.TenantID, authz.Certificate, id)
	})
	if err != nil {
		return err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.CertificateDeleted, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": row.SpiffeID, "serial": row.Serial},
	})
	return nil
}

// Renew reissues the same SPIFFE id from the same issuer with a fresh validity
// (matching the original lifetime) and marks the old certificate superseded.
// RenewSystemID is the SPIFFE identity the automated renewal scheduler acts as.
const RenewSystemID = "spiffe://system/lcm/renew"

// Renew reissues a certificate for a caller that holds use on it.
func (s *Service) Renew(ctx context.Context, subj authz.Subjects, certID string) (Bundle, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Use); err != nil {
		return Bundle{}, err
	}
	old, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return Bundle{}, err
	}
	return s.renewCert(ctx, subj, old)
}

// DownloadKey returns the sealed private key of a certificate whose key lcm
// retains (generic ACME certs). The caller needs use on the certificate. SVIDs
// clear their key after one-time delivery, so their key is unavailable here.
func (s *Service) DownloadKey(ctx context.Context, subj authz.Subjects, certID string) (string, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Use); err != nil {
		return "", err
	}
	c, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return "", err
	}
	if len(c.KeySealed) == 0 {
		return "", invalid("key", "no stored private key for this certificate")
	}
	clear, oerr := s.env.Open(c.KeySealed, sealed.ADCertKey(c.ID))
	if oerr != nil {
		return "", oerr
	}
	return string(clear), nil
}

// RenewSystem reissues a certificate as the automated renewal scheduler: a
// trusted, system-initiated operation that does not require a user grant. It
// is only reachable from in-process scheduler code, never from a request.
func (s *Service) RenewSystem(ctx context.Context, tenantID, certID string) (Bundle, error) {
	subj := authz.Subjects{TenantID: tenantID, Service: RenewSystemID, Roles: []string{"admin"}}
	old, err := s.st.GetCertificate(ctx, tenantID, certID)
	if err != nil {
		return Bundle{}, err
	}
	return s.renewCert(ctx, subj, old)
}

// renewCert mints a fresh certificate for the same SPIFFE id and supersedes old.
func (s *Service) renewCert(ctx context.Context, subj authz.Subjects, old store.IssuedCertificate) (Bundle, error) {
	// Generic (ACME) certificates renew by re-running the ACME order for the
	// same domains, reusing the stored key; SVIDs re-mint from the CA.
	if old.Kind == "generic" {
		return s.renewACME(ctx, subj, old)
	}
	sid, err := csr.ParseSPIFFEID(old.SpiffeID)
	if err != nil {
		return Bundle{}, invalid("spiffe_id", "stored SPIFFE ID is invalid")
	}
	issuer, err := s.st.GetIssuer(ctx, subj.TenantID, old.IssuerID)
	if err != nil {
		return Bundle{}, err
	}
	var sans []string
	if len(old.SANs) > 0 {
		_ = json.Unmarshal(old.SANs, &sans)
	}
	validity := int64(old.NotAfter.Sub(old.NotBefore) / time.Second)
	b, err := s.mint(ctx, subj, issuer, sid, mintReq{
		subject: old.Subject, dnsSans: sans, validitySeconds: validity, deliverKey: false,
		event: audit.CertificateRenewed, logEvent: "renewed",
	})
	if err != nil {
		return Bundle{}, err
	}
	newID := b.Certificate.ID
	if err := s.st.SetCertificateStatus(ctx, subj.TenantID, old.ID, old.Status, &newID); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Revoke marks a certificate revoked, records a revocation and logs it. The
// caller needs delete on the certificate.
func (s *Service) Revoke(ctx context.Context, subj authz.Subjects, certID, reason string) error {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Delete); err != nil {
		return err
	}
	row, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return err
	}
	if reason == "" {
		reason = "unspecified"
	}
	now := s.now()
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if serr := tx.SetCertificateStatus(ctx, subj.TenantID, certID, "revoked", nil); serr != nil {
			return serr
		}
		if rerr := tx.InsertRevocation(ctx, store.Revocation{
			ID: store.NewID(), TenantID: subj.TenantID, CertificateID: certID, Serial: row.Serial,
			Reason: reason, RevokedAt: now, RevokedBy: userPtr(subj),
		}); rerr != nil {
			return rerr
		}
		return tx.InsertCertLog(ctx, []store.CertLogRow{{
			TS: now, TenantID: subj.TenantID, CertificateID: certID, Event: "revoked", IssuerID: row.IssuerID, SpiffeID: row.SpiffeID,
		}})
	})
	if err != nil {
		return err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.CertificateRevoked, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": row.SpiffeID, "serial": row.Serial, "reason": reason},
	})
	return nil
}

// Download returns the certificate, its chain and the current trust bundle for a
// certificate the caller may read. It never returns key material.
// DownloadForService returns an issued certificate's bundle (and, when
// includeKey and lcm retains the key, the private key) to an authorized
// platform module. Like RenewSystem it is a trusted, service-initiated
// operation gated by the mTLS caller policy (policy.yaml, SR-003), not a user
// grant, so it acts with an elevated service subject. It is reachable only from
// the module gRPC surface, never from a browser request. The caller's SPIFFE id
// is recorded for audit.
func (s *Service) DownloadForService(ctx context.Context, tenantID, callerSPIFFE, certID string, includeKey bool) (Bundle, error) {
	subj := authz.Subjects{TenantID: tenantID, Service: callerSPIFFE, Roles: []string{"admin"}}
	b, err := s.Download(ctx, subj, certID)
	if err != nil {
		return Bundle{}, err
	}
	if includeKey {
		key, err := s.DownloadKey(ctx, subj, certID)
		if err != nil {
			return Bundle{}, err
		}
		b.KeyPEM = key
	}
	return b, nil
}

func (s *Service) Download(ctx context.Context, subj authz.Subjects, certID string) (Bundle, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Read); err != nil {
		return Bundle{}, err
	}
	row, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return Bundle{}, err
	}
	perms, _, _, err := s.az.Effective(ctx, subj, authz.Certificate, certID)
	if err != nil {
		return Bundle{}, err
	}
	bundlePEM := ""
	if sid, perr := csr.ParseSPIFFEID(row.SpiffeID); perr == nil {
		if bundlePEM, err = s.ca.Bundle(ctx, subj.TenantID, sid.TrustDomain); err != nil {
			return Bundle{}, err
		}
	}
	return Bundle{
		Certificate: s.certView(row, perms),
		CertPEM:     row.CertPEM,
		ChainPEM:    row.ChainPEM,
		BundlePEM:   bundlePEM,
	}, nil
}

// MarkKeyDelivered records that a certificate's generated key has been handed
// over, so it is never returned again. The caller needs use on the certificate.
func (s *Service) MarkKeyDelivered(ctx context.Context, subj authz.Subjects, certID string) error {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Use); err != nil {
		return err
	}
	return s.st.MarkKeyDelivered(ctx, subj.TenantID, certID)
}
