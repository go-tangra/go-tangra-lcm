// Package deploy records what workloads report as installed and lets an
// operator push an issued certificate to a deployment target. Actual webhook
// delivery is provided by the webhook package (US4); this package validates,
// records and audits the intent. Every operation is tenant-scoped (RLS) and
// the gateway gates the browser routes with certificates:manage / read.
package deploy

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

// Service records installations and deployment targets.
type Service struct {
	st    repoStore
	az    *authz.Authorizer
	env   *sealed.Envelope
	audit *audit.Writer
	now   func() time.Time
}

// repoStore is the persistence deploy needs (repo.Store satisfies it).
type repoStore interface {
	GetCertificate(ctx context.Context, tenantID, id string) (store.IssuedCertificate, error)
	UpsertInstalled(ctx context.Context, i store.InstalledCertificate) error
	ListInstalled(ctx context.Context, tenantID, clientID string, cursor time.Time, limit int) ([]store.InstalledCertificate, error)
	InsertTarget(ctx context.Context, t store.DeploymentTarget) error
	GetTarget(ctx context.Context, tenantID, id string) (store.DeploymentTarget, error)
	ListTargets(ctx context.Context, tenantID string) ([]store.DeploymentTarget, error)
}

// New builds the service.
func New(st repoStore, az *authz.Authorizer, env *sealed.Envelope, aw *audit.Writer, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{st: st, az: az, env: env, audit: aw, now: clock}
}

// InstalledView is one reported installation.
type InstalledView struct {
	CertificateID string    `json:"certificate_id"`
	ClientID      string    `json:"client_id"`
	InstalledAt   time.Time `json:"installed_at"`
	ReportedAt    time.Time `json:"reported_at"`
}

// ReportInstalled records that clientID installed certID. Called by a workload
// (gRPC Agent) or an operator; the caller must be able to read the certificate.
func (s *Service) ReportInstalled(ctx context.Context, subj authz.Subjects, certID, clientID string) error {
	if certID == "" || clientID == "" {
		return &ValidationError{Field: "certificate_id", Message: "certificate_id and client_id are required"}
	}
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Read); err != nil {
		return err
	}
	now := s.now()
	if err := s.st.UpsertInstalled(ctx, store.InstalledCertificate{
		ID: store.NewID(), TenantID: subj.TenantID, CertificateID: certID, ClientID: clientID,
		InstalledAt: now, ReportedAt: now,
	}); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateInstalled, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(), SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK})
	return nil
}

// ListInstalled lists installations, optionally filtered by client.
func (s *Service) ListInstalled(ctx context.Context, subj authz.Subjects, clientID string, cursor time.Time, limit int) ([]InstalledView, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if cursor.IsZero() {
		cursor = s.now()
	}
	rows, err := s.st.ListInstalled(ctx, subj.TenantID, clientID, cursor, limit)
	if err != nil {
		return nil, err
	}
	out := make([]InstalledView, 0, len(rows))
	for _, r := range rows {
		out = append(out, InstalledView{CertificateID: r.CertificateID, ClientID: r.ClientID, InstalledAt: r.InstalledAt, ReportedAt: r.ReportedAt})
	}
	return out, nil
}

// TargetInput creates a deployment target.
type TargetInput struct {
	Name   string
	Kind   string // file | pull | webhook
	Config sealed.Settings
}

// TargetView is a deployment target (credentials redacted).
type TargetView struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Config    sealed.Settings `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

var targetSecretFields = []string{"token", "password", "secret", "key"}

// CreateTarget registers a deployment target; credential config is sealed.
func (s *Service) CreateTarget(ctx context.Context, subj authz.Subjects, in TargetInput) (TargetView, error) {
	if l := len(in.Name); l < 1 || l > 100 {
		return TargetView{}, &ValidationError{Field: "name", Message: "name must be 1..100 chars"}
	}
	switch in.Kind {
	case "file", "pull", "webhook":
	default:
		return TargetView{}, &ValidationError{Field: "kind", Message: "kind must be file, pull or webhook"}
	}
	id := store.NewID()
	now := s.now()
	pub := sealed.Public(in.Config, targetSecretFields)
	pubBytes, err := sealed.Encode(pub)
	if err != nil {
		return TargetView{}, &ValidationError{Field: "config", Message: "config too large"}
	}
	var configSealed []byte
	if hasSecret(in.Config, targetSecretFields) {
		raw, err := sealed.Encode(in.Config)
		if err != nil {
			return TargetView{}, &ValidationError{Field: "config", Message: "config too large"}
		}
		if configSealed, err = s.env.Seal(raw, sealed.ADTarget(id)); err != nil {
			return TargetView{}, err
		}
	}
	actor := subj.ActorID()
	row := store.DeploymentTarget{ID: id, TenantID: subj.TenantID, Name: in.Name, Kind: in.Kind, ConfigPublic: pubBytes, ConfigSealed: configSealed, CreatedBy: &actor, UpdatedBy: &actor, CreatedAt: now, UpdatedAt: now}
	if err := s.st.InsertTarget(ctx, row); err != nil {
		return TargetView{}, err
	}
	_ = s.audit.Record(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateDeployed, ActorKind: subj.ActorKind(), ActorID: actor, SubjectKind: audit.SubjectSystem, SubjectID: id, SubjectName: in.Name, Outcome: audit.OutcomeOK})
	return s.view(row), nil
}

// ListTargets lists the tenant's deployment targets (credentials redacted).
func (s *Service) ListTargets(ctx context.Context, subj authz.Subjects) ([]TargetView, error) {
	rows, err := s.st.ListTargets(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]TargetView, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.view(r))
	}
	return out, nil
}

// Deploy validates that the caller may read the certificate and the target
// exists, then records the deployment intent (delivery is a webhook concern).
func (s *Service) Deploy(ctx context.Context, subj authz.Subjects, certID, targetID string) (TargetView, error) {
	if err := s.az.Check(ctx, subj, authz.Certificate, certID, authz.Write); err != nil {
		return TargetView{}, err
	}
	tgt, err := s.st.GetTarget(ctx, subj.TenantID, targetID)
	if err != nil {
		return TargetView{}, err
	}
	if _, err := s.st.GetCertificate(ctx, subj.TenantID, certID); err != nil {
		return TargetView{}, err
	}
	_ = s.audit.Record(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateDeployed, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(), SubjectKind: audit.SubjectCertificate, SubjectID: certID, SubjectName: tgt.Name, Outcome: audit.OutcomeOK})
	return s.view(tgt), nil
}

func (s *Service) view(r store.DeploymentTarget) TargetView {
	cfg, _ := sealed.Decode(r.ConfigPublic)
	if cfg == nil {
		cfg = sealed.Settings{}
	}
	if len(r.ConfigSealed) > 0 {
		for _, f := range targetSecretFields {
			cfg[f] = sealed.Marker
		}
	}
	return TargetView{ID: r.ID, Name: r.Name, Kind: r.Kind, Config: cfg, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func hasSecret(s sealed.Settings, fields []string) bool {
	for _, f := range fields {
		if v, ok := s[f]; ok {
			if str, _ := v.(string); str != "" && str != sealed.Marker {
				return true
			}
		}
	}
	return false
}

// ErrNotFound is returned when a target or certificate is absent.
var ErrNotFound = errors.New("deploy: not found")
