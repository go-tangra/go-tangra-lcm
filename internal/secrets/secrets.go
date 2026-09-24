// Package secrets manages per-tenant credentials (ACME account keys, DNS
// provider credentials) used by the issuer/ACME path. The credential value is
// write-only: it is sealed at rest with a per-row envelope and is NEVER
// returned in a view (SR-001); only server-side callers may open it through
// OpenValue. Every operation is tenant-scoped (RLS) and the gateway gates the
// browser routes with secrets:manage.
package secrets

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// ValidationError is a rejected input (field + message).
type ValidationError struct{ Field, Message string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// ConflictError reports a name clash or a secret still referenced by an issuer.
type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return e.Message }

// Kinds is the closed set of tenant-secret kinds.
const (
	KindACMEAccount   = "acme_account"
	KindDNSCredential = "dns_credential" // #nosec G101 -- a secret KIND label, not a credential value
)

// repoStore is the persistence the service needs (repo.Secrets satisfies it).
type repoStore interface {
	InsertSecret(ctx context.Context, s store.TenantSecret) error
	GetSecret(ctx context.Context, tenantID, id string) (store.TenantSecret, error)
	SecretByName(ctx context.Context, tenantID, name string) (store.TenantSecret, error)
	ListSecrets(ctx context.Context, tenantID string) ([]store.TenantSecret, error)
	UpdateSecret(ctx context.Context, s store.TenantSecret) error
	DeleteSecret(ctx context.Context, tenantID, id string) error
}

// Service stores and reads tenant secrets.
type Service struct {
	st    repoStore
	env   *sealed.Envelope
	audit *audit.Writer
	now   func() time.Time
}

// New builds the service.
func New(st repoStore, env *sealed.Envelope, aw *audit.Writer, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{st: st, env: env, audit: aw, now: clock}
}

// Input creates or replaces a tenant secret. Value is the credential material,
// sealed and never echoed back.
type Input struct {
	Name  string
	Kind  string
	Value sealed.Settings
}

// View is a tenant secret as returned to clients: metadata only. The credential
// value is write-only and NEVER present here (SR-001).
type View struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CreatedBy string    `json:"created_by"`
	UpdatedBy string    `json:"updated_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func validKind(k string) bool { return k == KindACMEAccount || k == KindDNSCredential }

// Create stores a new secret; the value is sealed with the secret's own
// associated data. The name is unique per tenant (case-insensitive).
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in Input) (View, error) {
	if l := len(in.Name); l < 1 || l > 100 {
		return View{}, &ValidationError{Field: "name", Message: "name must be 1..100 chars"}
	}
	if !validKind(in.Kind) {
		return View{}, &ValidationError{Field: "kind", Message: "kind must be acme_account or dns_credential"}
	}
	if len(in.Value) == 0 {
		return View{}, &ValidationError{Field: "value", Message: "value is required"}
	}
	if _, err := s.st.SecretByName(ctx, subj.TenantID, in.Name); err == nil {
		return View{}, &ConflictError{Message: "a secret with that name already exists"}
	} else if !errors.Is(err, store.ErrNotFound) {
		return View{}, err
	}
	id := store.NewID()
	blob, err := s.seal(id, in.Value)
	if err != nil {
		return View{}, err
	}
	actor := subj.ActorID()
	row := store.TenantSecret{ID: id, TenantID: subj.TenantID, Name: in.Name, Kind: in.Kind, ValueSealed: blob, CreatedBy: &actor, UpdatedBy: &actor}
	if err := s.st.InsertSecret(ctx, row); err != nil {
		return View{}, mapConflict(err)
	}
	s.record(ctx, subj, audit.SecretCreated, id, in.Name)
	return s.Get(ctx, subj, id)
}

// List returns the tenant's secrets (metadata only), ordered by name.
func (s *Service) List(ctx context.Context, subj authz.Subjects) ([]View, error) {
	rows, err := s.st.ListSecrets(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rows))
	for _, r := range rows {
		out = append(out, view(r))
	}
	return out, nil
}

// Get returns one secret's metadata. The value is never returned.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (View, error) {
	row, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, err
	}
	return view(row), nil
}

// Update renames a secret and merges its value: a value field sent as the
// marker (or omitted) keeps the stored value, "" clears it, any other value
// replaces it. The kind is immutable.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, id string, in Input) (View, error) {
	if l := len(in.Name); l < 1 || l > 100 {
		return View{}, &ValidationError{Field: "name", Message: "name must be 1..100 chars"}
	}
	row, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, err
	}
	stored, err := s.open(row)
	if err != nil {
		return View{}, err
	}
	if in.Value == nil {
		in.Value = sealed.Settings{}
	}
	merged := sealed.Merge(stored, in.Value, keysUnion(stored, in.Value))
	if len(merged) == 0 {
		return View{}, &ValidationError{Field: "value", Message: "value cannot be emptied"}
	}
	blob, err := s.seal(id, merged)
	if err != nil {
		return View{}, err
	}
	actor := subj.ActorID()
	row.Name, row.ValueSealed, row.UpdatedBy = in.Name, blob, &actor
	if err := s.st.UpdateSecret(ctx, row); err != nil {
		return View{}, mapConflict(err)
	}
	s.record(ctx, subj, audit.SecretUpdated, id, in.Name)
	return s.Get(ctx, subj, id)
}

// Rotate replaces the secret's value entirely (no merge).
func (s *Service) Rotate(ctx context.Context, subj authz.Subjects, id string, value sealed.Settings) (View, error) {
	if len(value) == 0 {
		return View{}, &ValidationError{Field: "value", Message: "value is required"}
	}
	row, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return View{}, err
	}
	blob, err := s.seal(id, value)
	if err != nil {
		return View{}, err
	}
	actor := subj.ActorID()
	row.ValueSealed, row.UpdatedBy = blob, &actor
	if err := s.st.UpdateSecret(ctx, row); err != nil {
		return View{}, mapConflict(err)
	}
	s.record(ctx, subj, audit.SecretRotated, id, row.Name)
	return s.Get(ctx, subj, id)
}

// Delete removes a secret. If an issuer still references it the store refuses
// with a conflict, surfaced here as a ConflictError.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	row, err := s.st.GetSecret(ctx, subj.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.st.DeleteSecret(ctx, subj.TenantID, id); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return &ConflictError{Message: "secret is still referenced by an issuer"}
		}
		return err
	}
	s.record(ctx, subj, audit.SecretDeleted, id, row.Name)
	return nil
}

// OpenValue decrypts a secret's credential value for the ACME/issuer path. It
// is server-side only and must never be exposed through an API.
func (s *Service) OpenValue(ctx context.Context, tenantID, id string) (sealed.Settings, error) {
	row, err := s.st.GetSecret(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.open(row)
}

// seal encodes and encrypts the clear value bound to the secret's associated data.
func (s *Service) seal(id string, value sealed.Settings) ([]byte, error) {
	clear, err := sealed.Encode(value)
	if err != nil {
		return nil, &ValidationError{Field: "value", Message: "value exceeds 8 KiB"}
	}
	blob, err := s.env.Seal(clear, sealed.ADSecret(id))
	if err != nil {
		if errors.Is(err, sealed.ErrTooLarge) {
			return nil, &ValidationError{Field: "value", Message: "value exceeds 8 KiB"}
		}
		return nil, err
	}
	return blob, nil
}

// open decrypts a secret's value (never leaves the service).
func (s *Service) open(row store.TenantSecret) (sealed.Settings, error) {
	clear, err := s.env.Open(row.ValueSealed, sealed.ADSecret(row.ID))
	if err != nil {
		return nil, err
	}
	return sealed.Decode(clear)
}

func (s *Service) record(ctx context.Context, subj authz.Subjects, t audit.EventType, id, name string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: t, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectSecret, SubjectID: id, SubjectName: name, Outcome: audit.OutcomeOK,
	})
}

func view(r store.TenantSecret) View {
	return View{ID: r.ID, Name: r.Name, Kind: r.Kind, CreatedBy: strp(r.CreatedBy), UpdatedBy: strp(r.UpdatedBy), CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func strp(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// mapConflict turns a store name clash into a ConflictError.
func mapConflict(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return &ConflictError{Message: "a secret with that name already exists"}
	}
	return err
}

// keysUnion is every key present in either settings map. For a tenant secret
// the whole value is credential material, so every field is treated as secret
// by Merge (marker/omitted keeps stored, "" clears, other replaces).
func keysUnion(a, b sealed.Settings) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for k := range a {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}
