package issue

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/acme"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// IssuerInput is a create/update request. Settings holds credential fields
// (ACME account key, DNS credential) that are sealed and never returned.
type IssuerInput struct {
	Name             string
	Type             string // self_signed | acme
	TrustDomain      string
	IsDefault        bool
	Enabled          bool
	ACMEDirectoryURL string
	ACMEEmail        string
	DNSProvider      string
	Settings         sealed.Settings
}

// IssuerView is an issuer as returned to clients. Settings is the redacted
// projection (credentials shown as the marker, never their values).
type IssuerView struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	TrustDomain      string            `json:"trust_domain"`
	IsDefault        bool              `json:"is_default"`
	CAID             string            `json:"ca_id,omitempty"`
	ACMEDirectoryURL string            `json:"acme_directory_url,omitempty"`
	ACMEEmail        string            `json:"acme_email,omitempty"`
	DNSProvider      string            `json:"dns_provider,omitempty"`
	Settings         sealed.Settings   `json:"settings"`
	Enabled          bool              `json:"enabled"`
	CertificateCount int               `json:"certificate_count"`
	CreatedBy        string            `json:"created_by"`
	UpdatedBy        string            `json:"updated_by"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	Permissions      authz.Permissions `json:"permissions"`
}

// validTrustDomain reports whether host is a non-empty run (<=253 bytes) of
// lowercase letters, digits, dots and hyphens.
func validTrustDomain(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// validate checks the shape of an issuer request.
func (s *Service) validate(in IssuerInput) error {
	if l := len(in.Name); l < 1 || l > 100 {
		return invalid("name", "name must be 1-100 characters")
	}
	if in.Type != "self_signed" && in.Type != "acme" {
		return invalid("type", "type must be self_signed or acme")
	}
	if !validTrustDomain(in.TrustDomain) {
		return invalid("trust_domain", "trust domain is not a valid host")
	}
	return nil
}

// seal encodes and seals the issuer settings and builds the redacted projection.
func (s *Service) seal(id string, in sealed.Settings) (blob, public []byte, err error) {
	if in == nil {
		in = sealed.Settings{}
	}
	clear, err := sealed.Encode(in)
	if err != nil {
		return nil, nil, invalid("settings", "settings exceed 8 KiB")
	}
	if blob, err = s.env.Seal(clear, sealed.ADIssuer(id)); err != nil {
		return nil, nil, err
	}
	if public, err = sealed.Encode(sealed.Redact(in, issuerSecretFields)); err != nil {
		return nil, nil, err
	}
	return blob, public, nil
}

// redacted decodes the stored public (already redacted) settings of a row.
func redacted(row store.Issuer) sealed.Settings {
	public, err := sealed.Decode(row.SettingsPublic)
	if err != nil || public == nil {
		return sealed.Settings{}
	}
	return public
}

// issuerView projects a row with its redacted settings and the caller's perms.
func issuerView(row store.Issuer, p authz.Permissions) IssuerView {
	return IssuerView{
		ID: row.ID, Name: row.Name, Type: row.Type, TrustDomain: row.TrustDomain, IsDefault: row.IsDefault,
		CAID: strp(row.CAID), ACMEDirectoryURL: row.ACMEDirectoryURL, ACMEEmail: row.ACMEEmail, DNSProvider: row.DNSProvider,
		Settings: redacted(row), Enabled: row.Enabled, CertificateCount: row.CertificateCount,
		CreatedBy: strp(row.CreatedBy), UpdatedBy: strp(row.UpdatedBy), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		Permissions: p,
	}
}

// CreateIssuer stores an issuer; the creator becomes its owner. A self-signed
// issuer references the tenant/trust-domain CA (generated on demand). A default
// issuer clears any previous default of the trust domain.
func (s *Service) CreateIssuer(ctx context.Context, subj authz.Subjects, in IssuerInput) (IssuerView, error) {
	if err := s.validate(in); err != nil {
		return IssuerView{}, err
	}
	// An ACME issuer needs an account key; generate one server-side (sealed,
	// never returned) when the caller did not supply one, so the UI can create
	// a working ACME issuer without the operator handling private-key PEM.
	if in.Type == "acme" {
		if err := ensureACMEAccountKey(&in); err != nil {
			return IssuerView{}, err
		}
	}
	id := store.NewID()
	blob, public, err := s.seal(id, in.Settings)
	if err != nil {
		return IssuerView{}, err
	}
	row := store.Issuer{
		ID: id, TenantID: subj.TenantID, Name: in.Name, Type: in.Type, TrustDomain: in.TrustDomain, IsDefault: in.IsDefault,
		ACMEDirectoryURL: in.ACMEDirectoryURL, ACMEEmail: in.ACMEEmail, DNSProvider: in.DNSProvider,
		SettingsPublic: public, SettingsSealed: blob, Enabled: in.Enabled, CreatedBy: userPtr(subj), UpdatedBy: userPtr(subj),
	}
	if in.Type == "self_signed" {
		caRow, cerr := s.ca.EnsureCA(ctx, subj.TenantID, in.TrustDomain)
		if cerr != nil {
			return IssuerView{}, cerr
		}
		caID := caRow.ID
		row.CAID = &caID
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if in.IsDefault {
			if derr := tx.ClearDefaultIssuer(ctx, subj.TenantID, in.TrustDomain, id); derr != nil {
				return derr
			}
		}
		if ierr := tx.InsertIssuer(ctx, row); ierr != nil {
			if errors.Is(ierr, store.ErrConflict) {
				return invalid("name", "an issuer with this name already exists")
			}
			return ierr
		}
		return authz.New(tx).GrantOwner(ctx, subj.TenantID, authz.Issuer, id, subj.UserID)
	})
	if err != nil {
		return IssuerView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.IssuerCreated, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectIssuer, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"name": in.Name, "type": in.Type, "trust_domain": in.TrustDomain, "is_default": in.IsDefault},
	})
	return s.GetIssuer(ctx, subj, id)
}

// ensureACMEAccountKey injects a freshly generated PKCS#8 ECDSA account key into
// the issuer settings when one is absent, so an ACME issuer is usable without
// the operator supplying key material. The key is sealed with the rest of the
// settings and never returned.
func ensureACMEAccountKey(in *IssuerInput) error {
	if in.Settings == nil {
		in.Settings = sealed.Settings{}
	}
	if v, ok := in.Settings["acme_account_key"]; ok {
		if str, _ := v.(string); str != "" {
			return nil
		}
	}
	key, err := acme.GenerateAccountKey()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	in.Settings["acme_account_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return nil
}

// GetIssuer returns an issuer the caller may read.
func (s *Service) GetIssuer(ctx context.Context, subj authz.Subjects, id string) (IssuerView, error) {
	if err := s.az.Check(ctx, subj, authz.Issuer, id, authz.Read); err != nil {
		return IssuerView{}, err
	}
	row, err := s.st.GetIssuer(ctx, subj.TenantID, id)
	if err != nil {
		return IssuerView{}, err
	}
	perms, _, _, err := s.az.Effective(ctx, subj, authz.Issuer, id)
	if err != nil {
		return IssuerView{}, err
	}
	return issuerView(row, perms), nil
}

// ListIssuers returns the issuers the caller may read, paged by name, plus the
// next cursor (the last issuer's name) when the page is full.
func (s *Service) ListIssuers(ctx context.Context, subj authz.Subjects, after string, limit int) ([]IssuerView, string, error) {
	ids, all, err := s.az.ListAccessibleIDs(ctx, subj, authz.Issuer)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	out := []IssuerView{}
	for len(out) < limit {
		rows, lerr := s.st.ListIssuers(ctx, subj.TenantID, after, limit)
		if lerr != nil {
			return nil, "", lerr
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			after = row.Name
			if !all && !ids[row.ID] {
				continue
			}
			perms, _, _, perr := s.az.Effective(ctx, subj, authz.Issuer, row.ID)
			if perr != nil {
				return nil, "", perr
			}
			out = append(out, issuerView(row, perms))
			if len(out) == limit {
				break
			}
		}
		if len(rows) < limit {
			break
		}
	}
	next := ""
	if len(out) == limit {
		next = out[len(out)-1].Name
	}
	return out, next, nil
}

// UpdateIssuer rewrites an issuer the caller may write; credential fields sent
// as the marker (or omitted) keep their stored value; the type is fixed.
func (s *Service) UpdateIssuer(ctx context.Context, subj authz.Subjects, id string, in IssuerInput) (IssuerView, error) {
	if err := s.az.Check(ctx, subj, authz.Issuer, id, authz.Write); err != nil {
		return IssuerView{}, err
	}
	row, err := s.st.GetIssuer(ctx, subj.TenantID, id)
	if err != nil {
		return IssuerView{}, err
	}
	if in.Type != "" && in.Type != row.Type {
		return IssuerView{}, invalid("type", "the issuer type cannot change")
	}
	in.Type, in.TrustDomain = row.Type, row.TrustDomain
	if err := s.validate(in); err != nil {
		return IssuerView{}, err
	}
	stored := sealed.Settings{}
	if len(row.SettingsSealed) > 0 {
		if clear, oerr := s.env.Open(row.SettingsSealed, sealed.ADIssuer(id)); oerr == nil {
			if dec, derr := sealed.Decode(clear); derr == nil {
				stored = dec
			}
		}
	}
	merged := sealed.Merge(stored, settingsOr(in.Settings), issuerSecretFields)
	blob, public, err := s.seal(id, merged)
	if err != nil {
		return IssuerView{}, err
	}
	wasDefault := row.IsDefault
	row.Name, row.IsDefault, row.Enabled = in.Name, in.IsDefault, in.Enabled
	row.ACMEDirectoryURL, row.ACMEEmail, row.DNSProvider = in.ACMEDirectoryURL, in.ACMEEmail, in.DNSProvider
	row.SettingsSealed, row.SettingsPublic, row.UpdatedBy = blob, public, userPtr(subj)
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if in.IsDefault && !wasDefault {
			if derr := tx.ClearDefaultIssuer(ctx, subj.TenantID, row.TrustDomain, id); derr != nil {
				return derr
			}
		}
		if uerr := tx.UpdateIssuer(ctx, row); uerr != nil {
			if errors.Is(uerr, store.ErrConflict) {
				return invalid("name", "an issuer with this name already exists")
			}
			return uerr
		}
		return nil
	})
	if err != nil {
		return IssuerView{}, err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.IssuerUpdated, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectIssuer, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"name": in.Name, "is_default": in.IsDefault, "enabled": in.Enabled},
	})
	return s.GetIssuer(ctx, subj, id)
}

// DeleteIssuer removes an issuer the caller may delete; issued certificates
// referencing it refuse the deletion with their count.
func (s *Service) DeleteIssuer(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.az.Check(ctx, subj, authz.Issuer, id, authz.Delete); err != nil {
		return err
	}
	row, err := s.st.GetIssuer(ctx, subj.TenantID, id)
	if err != nil {
		return err
	}
	if row.CertificateCount > 0 {
		return &InUseError{What: "certificates", Count: row.CertificateCount}
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if derr := tx.DeleteIssuer(ctx, subj.TenantID, id); derr != nil {
			if errors.Is(derr, store.ErrConflict) {
				return &InUseError{What: "certificates", Count: 1}
			}
			return derr
		}
		return authz.New(tx).DropResource(ctx, subj.TenantID, authz.Issuer, id)
	})
	if err != nil {
		return err
	}
	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: audit.IssuerDeleted, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectIssuer, SubjectID: id, Outcome: audit.OutcomeOK,
		Details: map[string]any{"name": row.Name},
	})
	return nil
}

// settingsOr returns a non-nil settings map.
func settingsOr(s sealed.Settings) sealed.Settings {
	if s == nil {
		return sealed.Settings{}
	}
	return s
}
