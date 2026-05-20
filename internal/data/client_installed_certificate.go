package data

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-lcm/internal/data/ent"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/clientinstalledcertificate"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

// ClientInstalledCertificateRepo manages the per-client record of which
// certificates an agent has actually installed locally. Used by deployer
// Verify (read) and the agent's report-back call (upsert).
type ClientInstalledCertificateRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewClientInstalledCertificateRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *ClientInstalledCertificateRepo {
	return &ClientInstalledCertificateRepo{
		log:       ctx.NewLoggerHelper("client_installed_certificate/repo"),
		entClient: entClient,
	}
}

// UpsertInput holds the fields supplied by an agent reporting an install.
type UpsertInput struct {
	TenantID          uint32
	ClientID          string
	Name              string
	SerialNumber      string
	FingerprintSHA256 string
	Status            clientinstalledcertificate.Status
	Message           string
	InstalledAt       time.Time
}

// Upsert inserts or updates the (tenant_id, client_id, name) row with the
// latest install state reported by the agent.
func (r *ClientInstalledCertificateRepo) Upsert(ctx context.Context, in UpsertInput) (*ent.ClientInstalledCertificate, error) {
	existing, err := r.entClient.Client().ClientInstalledCertificate.Query().
		Where(
			clientinstalledcertificate.TenantIDEQ(in.TenantID),
			clientinstalledcertificate.ClientIDEQ(in.ClientID),
			clientinstalledcertificate.NameEQ(in.Name),
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		r.log.Errorf("query installed cert failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query installed cert failed")
	}

	if existing == nil {
		builder := r.entClient.Client().ClientInstalledCertificate.Create().
			SetTenantID(in.TenantID).
			SetClientID(in.ClientID).
			SetName(in.Name).
			SetStatus(in.Status).
			SetCreateTime(time.Now())
		if in.SerialNumber != "" {
			builder.SetSerialNumber(in.SerialNumber)
		}
		if in.FingerprintSHA256 != "" {
			builder.SetFingerprintSha256(in.FingerprintSHA256)
		}
		if in.Message != "" {
			builder.SetMessage(in.Message)
		}
		if !in.InstalledAt.IsZero() {
			builder.SetInstalledAt(in.InstalledAt)
		}
		row, err := builder.Save(ctx)
		if err != nil {
			r.log.Errorf("create installed cert failed: %s", err.Error())
			return nil, lcmV1.ErrorInternalServerError("create installed cert failed")
		}
		return row, nil
	}

	update := existing.Update().
		SetStatus(in.Status).
		SetUpdateTime(time.Now())
	if in.SerialNumber != "" {
		update.SetSerialNumber(in.SerialNumber)
	}
	if in.FingerprintSHA256 != "" {
		update.SetFingerprintSha256(in.FingerprintSHA256)
	}
	if in.Message != "" {
		update.SetMessage(in.Message)
	} else {
		update.ClearMessage()
	}
	if !in.InstalledAt.IsZero() {
		update.SetInstalledAt(in.InstalledAt)
	}
	row, err := update.Save(ctx)
	if err != nil {
		r.log.Errorf("update installed cert failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update installed cert failed")
	}
	return row, nil
}

// ListForClients returns installed-cert rows for the given client_ids
// (within the optional tenant), optionally narrowed by certificate name.
func (r *ClientInstalledCertificateRepo) ListForClients(ctx context.Context, tenantID *uint32, clientIDs []string, name string) ([]*ent.ClientInstalledCertificate, error) {
	if len(clientIDs) == 0 {
		return nil, nil
	}
	q := r.entClient.Client().ClientInstalledCertificate.Query().
		Where(clientinstalledcertificate.ClientIDIn(clientIDs...))
	if tenantID != nil {
		q = q.Where(clientinstalledcertificate.TenantIDEQ(*tenantID))
	}
	if name != "" {
		q = q.Where(clientinstalledcertificate.NameEQ(name))
	}
	rows, err := q.All(ctx)
	if err != nil {
		r.log.Errorf("list installed certs failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("list installed certs failed")
	}
	return rows, nil
}

// ToProto converts an ent row to its proto representation.
func (r *ClientInstalledCertificateRepo) ToProto(row *ent.ClientInstalledCertificate) *lcmV1.InstalledCertificateInfo {
	if row == nil {
		return nil
	}
	info := &lcmV1.InstalledCertificateInfo{
		ClientId: &row.ClientID,
		Name:     &row.Name,
	}
	if row.TenantID != nil {
		tid := *row.TenantID
		info.TenantId = &tid
	}
	if row.SerialNumber != "" {
		s := row.SerialNumber
		info.SerialNumber = &s
	}
	if row.FingerprintSha256 != "" {
		s := row.FingerprintSha256
		info.FingerprintSha256 = &s
	}
	if row.Message != "" {
		s := row.Message
		info.Message = &s
	}
	if row.InstalledAt != nil {
		// Marshal via timestamppb at the service layer to avoid import here.
	}
	status := mapStatusToProto(row.Status)
	info.Status = &status
	return info
}

func mapStatusToProto(s clientinstalledcertificate.Status) lcmV1.InstalledCertificateStatus {
	switch s {
	case clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_INSTALLED:
		return lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_INSTALLED
	case clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_FAILED:
		return lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_FAILED
	case clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_REMOVED:
		return lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_REMOVED
	default:
		return lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_UNSPECIFIED
	}
}

// MapStatusFromProto maps the proto enum to the ent enum value.
func MapStatusFromProto(s lcmV1.InstalledCertificateStatus) clientinstalledcertificate.Status {
	switch s {
	case lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_INSTALLED:
		return clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_INSTALLED
	case lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_FAILED:
		return clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_FAILED
	case lcmV1.InstalledCertificateStatus_INSTALLED_CERT_STATUS_REMOVED:
		return clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_REMOVED
	default:
		return clientinstalledcertificate.StatusINSTALLED_CERT_STATUS_UNSPECIFIED
	}
}
