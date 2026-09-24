// Package transfer exports and imports tenant backups for the lifecycle
// service: issuers, issued-certificate metadata, permission grants and tenant
// secrets. Credentials (issuer sealed settings, tenant-secret values) travel
// ONLY on explicit request; a credential-free export carries no key material —
// no PEM private key, no sealed blob, no secret value (SR-001/SC-002). The
// document is validated whole against the schema and bounded in size and item
// count before any write; each entity is applied with skip or overwrite of
// duplicates.
package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-tangra/go-tangra-lcm/v4/api/schema"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Limits (the item bounds mirror the schema maxima; MaxItems is a combined
// defensive cap applied after decode).
const (
	MaxBytes = 16 << 20
	MaxDepth = 12
	MaxItems = 250000

	maxIssuers = 1000
	maxCerts   = 100000
	maxSecrets = 1000
	maxGrants  = 100000

	pageSize = 1000
)

// Errors.
var (
	ErrTooLarge = errors.New("transfer: document too large")
	ErrInvalid  = errors.New("transfer: invalid document")
	ErrMode     = errors.New("transfer: mode must be skip or overwrite")
)

// issuerSecretFields are the issuer settings that hold credential material and
// are excluded from a credential-free export.
var issuerSecretFields = []string{"acme_account_key", "dns_credential"}

// Document is the backup (api/schema/backup.schema.json).
type Document struct {
	Version             int           `json:"version"`
	ExportedAt          time.Time     `json:"exported_at"`
	Tenant              string        `json:"tenant"`
	IncludesCredentials bool          `json:"includes_credentials"`
	Issuers             []Issuer      `json:"issuers"`
	Certificates        []Certificate `json:"certificates"`
	Permissions         []Permission  `json:"permissions"`
	Secrets             []Secret      `json:"tenant_secrets,omitempty"`
}

// Issuer is an exported signing authority. Settings holds the non-secret
// configuration; Credentials (sealed account key / DNS credential) is present
// only when the export includes credentials.
type Issuer struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	TrustDomain string          `json:"trust_domain"`
	IsDefault   bool            `json:"is_default"`
	Settings    sealed.Settings `json:"settings,omitempty"`
	Credentials sealed.Settings `json:"credentials,omitempty"`
}

// Certificate is exported issued-certificate metadata. It never carries the
// private key: only the public certificate/chain PEM and descriptive fields.
type Certificate struct {
	Serial            string    `json:"serial"`
	SpiffeID          string    `json:"spiffe_id"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject,omitempty"`
	SANs              []string  `json:"sans,omitempty"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	Status            string    `json:"status"`
	CertPEM           string    `json:"cert_pem,omitempty"`
	ChainPEM          string    `json:"chain_pem,omitempty"`
}

// Permission is an exported relation grant. ResourceRef is the issuer name or
// the certificate serial (the stable reference across a restore).
type Permission struct {
	ResourceType string     `json:"resource_type"`
	ResourceRef  string     `json:"resource_ref"`
	SubjectType  string     `json:"subject_type"`
	SubjectID    string     `json:"subject_id,omitempty"`
	Relation     string     `json:"relation"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// Secret is an exported tenant secret. Value is the JSON-encoded credential
// object, present only when the export includes credentials.
type Secret struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

// Report is the import outcome. Created counts entities written (a new insert,
// or an overwrite of a duplicate in overwrite mode); Skipped counts duplicates
// left untouched (and certificates whose issuer is missing).
type Report struct {
	IssuersCreated      int `json:"issuers_created"`
	IssuersSkipped      int `json:"issuers_skipped"`
	CertificatesCreated int `json:"certificates_created"`
	CertificatesSkipped int `json:"certificates_skipped"`
	GrantsCreated       int `json:"grants_created"`
	SecretsCreated      int `json:"secrets_created"`
}

var backupSchema = func() *jsonschema.Schema {
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Backup))
	if err != nil {
		panic(err)
	}
	if err := c.AddResource("backup.schema.json", doc); err != nil {
		panic(err)
	}
	return c.MustCompile("backup.schema.json")
}()

// Service exports and imports tenant backups.
type Service struct {
	st    repo.Store
	env   *sealed.Envelope
	audit *audit.Writer
	now   func() time.Time
}

// New wires the service.
func New(st repo.Store, env *sealed.Envelope, aw *audit.Writer, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{st: st, env: env, audit: aw, now: clock}
}

// Export builds the document for the caller's tenant. Certificate private keys
// are never read; credentials (issuer sealed settings, tenant-secret values)
// are opened and re-serialised only when includeCredentials is set. The bulk
// disclosure is audited distinctly.
func (s *Service) Export(ctx context.Context, subj authz.Subjects, includeCredentials bool) (*Document, error) {
	doc := &Document{
		Version: 1, ExportedAt: s.now(), Tenant: subj.TenantID, IncludesCredentials: includeCredentials,
		Issuers: []Issuer{}, Certificates: []Certificate{}, Permissions: []Permission{},
	}

	issuers, err := s.st.ListIssuers(ctx, subj.TenantID, "", maxIssuers)
	if err != nil {
		return nil, err
	}
	issuerNameByID := make(map[string]string, len(issuers))
	for _, i := range issuers {
		issuerNameByID[i.ID] = i.Name
		item := Issuer{Name: i.Name, Type: i.Type, TrustDomain: i.TrustDomain, IsDefault: i.IsDefault, Settings: publicIssuerSettings(i)}
		if includeCredentials {
			full, oerr := s.openIssuer(i)
			if oerr != nil {
				return nil, oerr
			}
			if creds := onlyFields(full, issuerSecretFields); len(creds) > 0 {
				item.Credentials = creds
			}
		}
		doc.Issuers = append(doc.Issuers, item)
	}

	certs, err := s.listAllCertificates(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	certSerialByID := make(map[string]string, len(certs))
	for _, c := range certs {
		certSerialByID[c.ID] = c.Serial
		doc.Certificates = append(doc.Certificates, Certificate{
			Serial: c.Serial, SpiffeID: c.SpiffeID, Issuer: issuerNameByID[c.IssuerID], Subject: c.Subject,
			SANs: decodeSANs(c.SANs), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			FingerprintSHA256: c.FingerprintSHA256, Status: c.Status, CertPEM: c.CertPEM, ChainPEM: c.ChainPEM,
		})
	}

	// Grants, keyed by the stable reference (issuer name / certificate serial).
	for _, i := range issuers {
		grants, gerr := s.st.GrantsOnResource(ctx, subj.TenantID, authz.Issuer, i.ID)
		if gerr != nil {
			return nil, gerr
		}
		for _, g := range grants {
			doc.Permissions = append(doc.Permissions, permissionOf(g, i.Name))
		}
	}
	for _, c := range certs {
		grants, gerr := s.st.GrantsOnResource(ctx, subj.TenantID, authz.Certificate, c.ID)
		if gerr != nil {
			return nil, gerr
		}
		for _, g := range grants {
			doc.Permissions = append(doc.Permissions, permissionOf(g, c.Serial))
		}
	}

	if includeCredentials {
		secrets, serr := s.st.ListSecrets(ctx, subj.TenantID)
		if serr != nil {
			return nil, serr
		}
		doc.Secrets = []Secret{}
		for _, sec := range secrets {
			value, oerr := s.openSecret(sec)
			if oerr != nil {
				return nil, oerr
			}
			doc.Secrets = append(doc.Secrets, Secret{Name: sec.Name, Kind: sec.Kind, Value: value})
		}
	}

	evt := audit.BackupExported
	if includeCredentials {
		evt = audit.BackupExportedWithCredentials
	}
	s.record(ctx, subj, evt, map[string]any{
		"issuers": len(doc.Issuers), "certificates": len(doc.Certificates),
		"permissions": len(doc.Permissions), "credentials": includeCredentials,
	})
	return doc, nil
}

// DecodeBounded parses a document within the size, depth and item bounds and
// validates it against the schema. Anything the schema rejects is refused.
func DecodeBounded(raw []byte) (*Document, error) {
	if len(raw) > MaxBytes {
		return nil, ErrTooLarge
	}
	if depth(raw) > MaxDepth {
		return nil, fmt.Errorf("%w: nesting too deep", ErrInvalid)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("%w: not JSON", ErrInvalid)
	}
	if err := backupSchema.Validate(generic); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, firstLine(err.Error()))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if len(doc.Issuers)+len(doc.Certificates)+len(doc.Permissions)+len(doc.Secrets) > MaxItems {
		return nil, fmt.Errorf("%w: more than %d items", ErrInvalid, MaxItems)
	}
	return &doc, nil
}

// Import applies a document with mode "skip" or "overwrite" (issuers matched by
// name, certificates by serial, secrets by name). Every write runs in one
// transaction. Imported credentials are re-sealed with the associated data of
// the new ids.
func (s *Service) Import(ctx context.Context, subj authz.Subjects, doc *Document, mode string) (Report, error) {
	if mode != "skip" && mode != "overwrite" {
		return Report{}, ErrMode
	}
	if len(doc.Issuers) > maxIssuers || len(doc.Certificates) > maxCerts ||
		len(doc.Secrets) > maxSecrets || len(doc.Permissions) > maxGrants {
		return Report{}, fmt.Errorf("%w: too many items", ErrInvalid)
	}
	actor := subj.ActorID()
	var actorPtr *string
	if actor != "" {
		actorPtr = &actor
	}

	var rep Report
	err := s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		issuerIDByName, err := s.importIssuers(ctx, tx, subj, doc, mode, actorPtr, &rep)
		if err != nil {
			return err
		}
		certIDBySerial, err := s.importCertificates(ctx, tx, subj, doc, mode, issuerIDByName, actor, actorPtr, &rep)
		if err != nil {
			return err
		}
		if err := s.importGrants(ctx, tx, subj, doc, issuerIDByName, certIDBySerial, actorPtr, &rep); err != nil {
			return err
		}
		return s.importSecrets(ctx, tx, subj, doc, mode, actorPtr, &rep)
	})
	if err != nil {
		return Report{}, err
	}
	s.record(ctx, subj, audit.BackupImported, map[string]any{
		"mode": mode, "issuers_created": rep.IssuersCreated, "certificates_created": rep.CertificatesCreated,
		"grants_created": rep.GrantsCreated,
	})
	return rep, nil
}

func (s *Service) importIssuers(ctx context.Context, tx repo.Store, subj authz.Subjects, doc *Document, mode string, actorPtr *string, rep *Report) (map[string]string, error) {
	existing, err := tx.ListIssuers(ctx, subj.TenantID, "", maxIssuers)
	if err != nil {
		return nil, err
	}
	idByName := make(map[string]string, len(existing)+len(doc.Issuers))
	for _, i := range existing {
		idByName[lower(i.Name)] = i.ID
	}
	for _, di := range doc.Issuers {
		if existingID, ok := idByName[lower(di.Name)]; ok {
			if mode == "skip" {
				rep.IssuersSkipped++
				continue
			}
			row, gerr := tx.GetIssuer(ctx, subj.TenantID, existingID)
			if gerr != nil {
				return nil, gerr
			}
			creds := di.Credentials
			if len(creds) == 0 { // a credential-free overwrite keeps the stored credential
				if full, oerr := s.openIssuer(row); oerr == nil {
					creds = onlyFields(full, issuerSecretFields)
				}
			}
			blob, public, serr := s.sealIssuer(existingID, di.Settings, creds)
			if serr != nil {
				return nil, serr
			}
			row.Type, row.TrustDomain, row.IsDefault = di.Type, di.TrustDomain, di.IsDefault
			row.SettingsSealed, row.SettingsPublic, row.UpdatedBy = blob, public, actorPtr
			if uerr := tx.UpdateIssuer(ctx, row); uerr != nil {
				return nil, uerr
			}
			rep.IssuersCreated++
			continue
		}
		id := store.NewID()
		blob, public, serr := s.sealIssuer(id, di.Settings, di.Credentials)
		if serr != nil {
			return nil, serr
		}
		row := store.Issuer{
			ID: id, TenantID: subj.TenantID, Name: di.Name, Type: di.Type, TrustDomain: di.TrustDomain,
			IsDefault: di.IsDefault, SettingsPublic: public, SettingsSealed: blob, Enabled: true,
			CreatedBy: actorPtr, UpdatedBy: actorPtr,
		}
		if ierr := tx.InsertIssuer(ctx, row); ierr != nil {
			if errors.Is(ierr, store.ErrConflict) {
				rep.IssuersSkipped++
				continue
			}
			return nil, ierr
		}
		idByName[lower(di.Name)] = id
		rep.IssuersCreated++
	}
	return idByName, nil
}

func (s *Service) importCertificates(ctx context.Context, tx repo.Store, subj authz.Subjects, doc *Document, mode string, issuerIDByName map[string]string, actor string, actorPtr *string, rep *Report) (map[string]string, error) {
	existing, err := s.listAllCertificatesTx(ctx, tx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	idBySerial := make(map[string]string, len(existing)+len(doc.Certificates))
	for _, c := range existing {
		idBySerial[c.Serial] = c.ID
	}
	for _, dc := range doc.Certificates {
		issuerID, ok := issuerIDByName[lower(dc.Issuer)]
		if !ok {
			rep.CertificatesSkipped++
			continue
		}
		if existingID, ok := idBySerial[dc.Serial]; ok {
			if mode == "skip" {
				rep.CertificatesSkipped++
				continue
			}
			row, gerr := tx.GetCertificate(ctx, subj.TenantID, existingID)
			if gerr != nil {
				return nil, gerr
			}
			row.Status, row.ChainPEM, row.UpdatedBy = dc.Status, dc.ChainPEM, actorPtr
			if uerr := tx.UpdateCertificate(ctx, row); uerr != nil {
				return nil, uerr
			}
			rep.CertificatesCreated++
			continue
		}
		sans, _ := json.Marshal(nonNilStrings(dc.SANs))
		owner := dc.SpiffeID
		if owner == "" {
			owner = actor
		}
		row := store.IssuedCertificate{
			ID: store.NewID(), TenantID: subj.TenantID, IssuerID: issuerID, Serial: dc.Serial, SpiffeID: dc.SpiffeID,
			Subject: dc.Subject, SANs: sans, NotBefore: dc.NotBefore, NotAfter: dc.NotAfter,
			FingerprintSHA256: dc.FingerprintSHA256, Status: dc.Status, CertPEM: dc.CertPEM, ChainPEM: dc.ChainPEM,
			Owner: owner, CreatedBy: actorPtr, UpdatedBy: actorPtr,
		}
		if ierr := tx.InsertCertificate(ctx, row); ierr != nil {
			if errors.Is(ierr, store.ErrConflict) {
				rep.CertificatesSkipped++
				continue
			}
			return nil, ierr
		}
		idBySerial[dc.Serial] = row.ID
		rep.CertificatesCreated++
	}
	return idBySerial, nil
}

func (s *Service) importGrants(ctx context.Context, tx repo.Store, subj authz.Subjects, doc *Document, issuerIDByName, certIDBySerial map[string]string, actorPtr *string, rep *Report) error {
	for _, dp := range doc.Permissions {
		var resourceID string
		switch dp.ResourceType {
		case authz.Issuer:
			resourceID = issuerIDByName[lower(dp.ResourceRef)]
		case authz.Certificate:
			resourceID = certIDBySerial[dp.ResourceRef]
		}
		if resourceID == "" {
			continue // the referenced resource is not part of this import
		}
		g := store.Grant{
			ID: store.NewID(), TenantID: subj.TenantID, ResourceType: dp.ResourceType, ResourceID: resourceID,
			SubjectType: dp.SubjectType, SubjectID: dp.SubjectID, Relation: dp.Relation, GrantedBy: actorPtr, ExpiresAt: dp.ExpiresAt,
		}
		if _, gerr := tx.UpsertGrant(ctx, g); gerr != nil {
			return gerr
		}
		rep.GrantsCreated++
	}
	return nil
}

func (s *Service) importSecrets(ctx context.Context, tx repo.Store, subj authz.Subjects, doc *Document, mode string, actorPtr *string, rep *Report) error {
	for _, ds := range doc.Secrets {
		existing, gerr := tx.SecretByName(ctx, subj.TenantID, ds.Name)
		switch {
		case gerr == nil:
			if mode == "skip" {
				continue
			}
			blob, serr := s.sealSecretValue(existing.ID, ds.Value)
			if serr != nil {
				return serr
			}
			existing.Kind, existing.ValueSealed, existing.UpdatedBy = ds.Kind, blob, actorPtr
			if uerr := tx.UpdateSecret(ctx, existing); uerr != nil {
				return uerr
			}
			continue
		case !errors.Is(gerr, store.ErrNotFound):
			return gerr
		}
		id := store.NewID()
		blob, serr := s.sealSecretValue(id, ds.Value)
		if serr != nil {
			return serr
		}
		row := store.TenantSecret{ID: id, TenantID: subj.TenantID, Name: ds.Name, Kind: ds.Kind, ValueSealed: blob, CreatedBy: actorPtr, UpdatedBy: actorPtr}
		if ierr := tx.InsertSecret(ctx, row); ierr != nil {
			if errors.Is(ierr, store.ErrConflict) {
				continue
			}
			return ierr
		}
		rep.SecretsCreated++
	}
	return nil
}

// ---- credential helpers

// openIssuer decrypts the full stored issuer settings (server-side only).
func (s *Service) openIssuer(row store.Issuer) (sealed.Settings, error) {
	if len(row.SettingsSealed) == 0 {
		return sealed.Settings{}, nil
	}
	clear, err := s.env.Open(row.SettingsSealed, sealed.ADIssuer(row.ID))
	if err != nil {
		return nil, err
	}
	return sealed.Decode(clear)
}

// openSecret decrypts a tenant secret and returns its JSON-encoded value.
func (s *Service) openSecret(row store.TenantSecret) (string, error) {
	clear, err := s.env.Open(row.ValueSealed, sealed.ADSecret(row.ID))
	if err != nil {
		return "", err
	}
	value, err := sealed.Decode(clear)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// sealIssuer seals the combined public+credential settings under the id's
// associated data and builds the redacted public projection.
func (s *Service) sealIssuer(id string, settings, creds sealed.Settings) (blob, public []byte, err error) {
	full := sealed.Settings{}
	for k, v := range settings {
		full[k] = v
	}
	for k, v := range creds {
		full[k] = v
	}
	clear, err := sealed.Encode(full)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: issuer settings", ErrInvalid)
	}
	if blob, err = s.env.Seal(clear, sealed.ADIssuer(id)); err != nil {
		return nil, nil, err
	}
	if public, err = sealed.Encode(sealed.Redact(full, issuerSecretFields)); err != nil {
		return nil, nil, err
	}
	return blob, public, nil
}

// sealSecretValue re-seals a tenant secret's JSON value under the id's
// associated data.
func (s *Service) sealSecretValue(id, value string) ([]byte, error) {
	settings, err := sealed.Decode([]byte(value))
	if err != nil {
		return nil, fmt.Errorf("%w: secret value", ErrInvalid)
	}
	clear, err := sealed.Encode(settings)
	if err != nil {
		return nil, fmt.Errorf("%w: secret value", ErrInvalid)
	}
	blob, err := s.env.Seal(clear, sealed.ADSecret(id))
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func (s *Service) record(ctx context.Context, subj authz.Subjects, evt audit.EventType, details map[string]any) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: evt, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectBackup, SubjectID: subj.TenantID, Outcome: audit.OutcomeOK, Details: details,
	})
}

// ---- reads

func (s *Service) listAllCertificates(ctx context.Context, tenantID string) ([]store.IssuedCertificate, error) {
	return pageCertificates(func(f store.CertificateFilter) ([]store.IssuedCertificate, error) {
		return s.st.ListCertificates(ctx, tenantID, f)
	})
}

func (s *Service) listAllCertificatesTx(ctx context.Context, tx repo.Store, tenantID string) ([]store.IssuedCertificate, error) {
	return pageCertificates(func(f store.CertificateFilter) ([]store.IssuedCertificate, error) {
		return tx.ListCertificates(ctx, tenantID, f)
	})
}

func pageCertificates(list func(store.CertificateFilter) ([]store.IssuedCertificate, error)) ([]store.IssuedCertificate, error) {
	var out []store.IssuedCertificate
	f := store.CertificateFilter{Limit: pageSize}
	for {
		batch, err := list(f)
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < f.Limit || len(out) >= maxCerts {
			break
		}
		last := batch[len(batch)-1]
		f.CursorTS, f.CursorID = last.CreatedAt, last.ID
	}
	return out, nil
}

// ---- pure helpers

func permissionOf(g store.Grant, ref string) Permission {
	return Permission{
		ResourceType: g.ResourceType, ResourceRef: ref, SubjectType: g.SubjectType,
		SubjectID: g.SubjectID, Relation: g.Relation, ExpiresAt: g.ExpiresAt,
	}
}

// publicIssuerSettings returns the stored non-secret settings with any redaction
// marker removed, so a credential-free export carries no secret placeholders.
func publicIssuerSettings(row store.Issuer) sealed.Settings {
	p, err := sealed.Decode(row.SettingsPublic)
	if err != nil || p == nil {
		return sealed.Settings{}
	}
	return sealed.Public(p, issuerSecretFields)
}

// onlyFields returns the present, non-empty credential fields.
func onlyFields(s sealed.Settings, fields []string) sealed.Settings {
	out := sealed.Settings{}
	for _, f := range fields {
		if v, ok := s[f]; ok {
			if str, isStr := v.(string); isStr && str == "" {
				continue
			}
			out[f] = v
		}
	}
	return out
}

func decodeSANs(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var out []string
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func lower(s string) string { return strings.ToLower(s) }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// depth measures JSON nesting without building the tree.
func depth(raw []byte) int {
	d, max := 0, 0
	inStr, esc := false, false
	for _, b := range raw {
		switch {
		case esc:
			esc = false
		case inStr && b == '\\':
			esc = true
		case b == '"':
			inStr = !inStr
		case inStr:
		case b == '{' || b == '[':
			d++
			if d > max {
				max = d
			}
		case b == '}' || b == ']':
			d--
		}
	}
	return max
}
