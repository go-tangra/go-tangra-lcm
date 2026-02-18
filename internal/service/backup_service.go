package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-common/grpcx"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/certificatepermission"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/issuedcertificate"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/issuer"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/lcmca"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/lcmclient"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/mtlscertificate"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/mtlscertificaterequest"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/tenantsecret"
)

const (
	backupModule  = "lcm"
	backupVersion = "1.0"
)

type BackupService struct {
	lcmV1.UnimplementedBackupServiceServer

	log       *log.Helper
	entClient *entCrud.EntClient[*ent.Client]
}

func NewBackupService(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *BackupService {
	return &BackupService{
		log:       ctx.NewLoggerHelper("lcm/service/backup"),
		entClient: entClient,
	}
}

type backupData struct {
	Module     string         `json:"module"`
	Version    string         `json:"version"`
	ExportedAt time.Time     `json:"exportedAt"`
	TenantID   uint32        `json:"tenantId"`
	FullBackup bool          `json:"fullBackup"`
	Data       backupEntities `json:"data"`
}

type backupEntities struct {
	LcmClients               []json.RawMessage `json:"lcmClients,omitempty"`
	LcmCa                    []json.RawMessage `json:"lcmCa,omitempty"`
	TenantSecrets            []json.RawMessage `json:"tenantSecrets,omitempty"`
	Issuers                  []json.RawMessage `json:"issuers,omitempty"`
	SelfSignedIssuers        []json.RawMessage `json:"selfSignedIssuers,omitempty"`
	AcmeIssuers              []json.RawMessage `json:"acmeIssuers,omitempty"`
	IssuedCertificates       []json.RawMessage `json:"issuedCertificates,omitempty"`
	CertificateDetails       []json.RawMessage `json:"certificateDetails,omitempty"`
	CertificateRequests      []json.RawMessage `json:"certificateRequests,omitempty"`
	CertificatePermissions   []json.RawMessage `json:"certificatePermissions,omitempty"`
	CertificateRenewals      []json.RawMessage `json:"certificateRenewals,omitempty"`
	MtlsCertificates         []json.RawMessage `json:"mtlsCertificates,omitempty"`
	MtlsCertificateRequests  []json.RawMessage `json:"mtlsCertificateRequests,omitempty"`
}

func marshalEntities[T any](entities []*T) ([]json.RawMessage, error) {
	result := make([]json.RawMessage, 0, len(entities))
	for _, e := range entities {
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}

func (s *BackupService) ExportBackup(ctx context.Context, req *lcmV1.ExportBackupRequest) (*lcmV1.ExportBackupResponse, error) {
	tenantID := grpcx.GetTenantIDFromContext(ctx)
	full := false

	if grpcx.IsPlatformAdmin(ctx) && req.TenantId != nil && *req.TenantId == 0 {
		full = true
		tenantID = 0
	} else if req.TenantId != nil && *req.TenantId != 0 {
		if grpcx.IsPlatformAdmin(ctx) {
			tenantID = *req.TenantId
		}
	}

	client := s.entClient.Client()
	now := time.Now()

	lcmClients, err := s.exportLcmClients(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export lcm clients: %w", err)
	}
	lcmCa, err := s.exportLcmCa(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export lcm ca: %w", err)
	}
	tenantSecrets, err := s.exportTenantSecrets(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export tenant secrets: %w", err)
	}
	issuers, err := s.exportIssuers(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export issuers: %w", err)
	}
	selfSignedIssuers, err := s.exportSelfSignedIssuers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("export self signed issuers: %w", err)
	}
	acmeIssuers, err := s.exportAcmeIssuers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("export acme issuers: %w", err)
	}
	issuedCertificates, err := s.exportIssuedCertificates(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export issued certificates: %w", err)
	}
	certificateDetails, err := s.exportCertificateDetails(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("export certificate details: %w", err)
	}
	certificateRequests, err := s.exportCertificateRequests(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("export certificate requests: %w", err)
	}
	certificatePermissions, err := s.exportCertificatePermissions(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export certificate permissions: %w", err)
	}
	certificateRenewals, err := s.exportCertificateRenewals(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("export certificate renewals: %w", err)
	}
	mtlsCertificates, err := s.exportMtlsCertificates(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export mtls certificates: %w", err)
	}
	mtlsCertificateRequests, err := s.exportMtlsCertificateRequests(ctx, client, tenantID, full)
	if err != nil {
		return nil, fmt.Errorf("export mtls certificate requests: %w", err)
	}

	backup := backupData{
		Module:     backupModule,
		Version:    backupVersion,
		ExportedAt: now,
		TenantID:   tenantID,
		FullBackup: full,
		Data: backupEntities{
			LcmClients:              lcmClients,
			LcmCa:                   lcmCa,
			TenantSecrets:           tenantSecrets,
			Issuers:                 issuers,
			SelfSignedIssuers:       selfSignedIssuers,
			AcmeIssuers:             acmeIssuers,
			IssuedCertificates:      issuedCertificates,
			CertificateDetails:      certificateDetails,
			CertificateRequests:     certificateRequests,
			CertificatePermissions:  certificatePermissions,
			CertificateRenewals:     certificateRenewals,
			MtlsCertificates:        mtlsCertificates,
			MtlsCertificateRequests: mtlsCertificateRequests,
		},
	}

	data, err := json.Marshal(backup)
	if err != nil {
		return nil, fmt.Errorf("marshal backup: %w", err)
	}

	entityCounts := map[string]int64{
		"lcmClients":              int64(len(lcmClients)),
		"lcmCa":                   int64(len(lcmCa)),
		"tenantSecrets":           int64(len(tenantSecrets)),
		"issuers":                 int64(len(issuers)),
		"selfSignedIssuers":       int64(len(selfSignedIssuers)),
		"acmeIssuers":             int64(len(acmeIssuers)),
		"issuedCertificates":      int64(len(issuedCertificates)),
		"certificateDetails":      int64(len(certificateDetails)),
		"certificateRequests":     int64(len(certificateRequests)),
		"certificatePermissions":  int64(len(certificatePermissions)),
		"certificateRenewals":     int64(len(certificateRenewals)),
		"mtlsCertificates":        int64(len(mtlsCertificates)),
		"mtlsCertificateRequests": int64(len(mtlsCertificateRequests)),
	}

	s.log.Infof("exported backup: module=%s tenant=%d full=%v entities=%v", backupModule, tenantID, full, entityCounts)

	return &lcmV1.ExportBackupResponse{
		Data:         data,
		Module:       backupModule,
		Version:      backupVersion,
		ExportedAt:   timestamppb.New(now),
		TenantId:     tenantID,
		EntityCounts: entityCounts,
	}, nil
}

func (s *BackupService) ImportBackup(ctx context.Context, req *lcmV1.ImportBackupRequest) (*lcmV1.ImportBackupResponse, error) {
	tenantID := grpcx.GetTenantIDFromContext(ctx)
	isPlatformAdmin := grpcx.IsPlatformAdmin(ctx)
	mode := req.GetMode()

	var backup backupData
	if err := json.Unmarshal(req.GetData(), &backup); err != nil {
		return nil, fmt.Errorf("invalid backup data: %w", err)
	}

	if backup.Module != backupModule {
		return nil, fmt.Errorf("backup module mismatch: expected %s, got %s", backupModule, backup.Module)
	}
	if backup.Version != backupVersion {
		return nil, fmt.Errorf("backup version mismatch: expected %s, got %s", backupVersion, backup.Version)
	}

	// For full backups, only platform admins can restore
	if backup.FullBackup && !isPlatformAdmin {
		return nil, fmt.Errorf("only platform admins can restore full backups")
	}

	// Non-platform admins always restore to their own tenant
	if !isPlatformAdmin || !backup.FullBackup {
		tenantID = grpcx.GetTenantIDFromContext(ctx)
	} else {
		tenantID = 0 // Signal for full backup restore — each entity carries its own tenant_id
	}

	client := s.entClient.Client()
	var results []*lcmV1.EntityImportResult
	var warnings []string

	// Import in FK dependency order
	importFuncs := []struct {
		name string
		fn   func(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string)
	}{
		{"lcmClients", s.importLcmClients},
		{"lcmCa", s.importLcmCa},
		{"tenantSecrets", s.importTenantSecrets},
		{"issuers", s.importIssuers},
		{"selfSignedIssuers", s.importSelfSignedIssuers},
		{"acmeIssuers", s.importAcmeIssuers},
		{"issuedCertificates", s.importIssuedCertificates},
		{"certificateDetails", s.importCertificateDetails},
		{"certificateRequests", s.importCertificateRequests},
		{"certificatePermissions", s.importCertificatePermissions},
		{"certificateRenewals", s.importCertificateRenewals},
		{"mtlsCertificates", s.importMtlsCertificates},
		{"mtlsCertificateRequests", s.importMtlsCertificateRequests},
	}

	dataMap := map[string][]json.RawMessage{
		"lcmClients":              backup.Data.LcmClients,
		"lcmCa":                   backup.Data.LcmCa,
		"tenantSecrets":           backup.Data.TenantSecrets,
		"issuers":                 backup.Data.Issuers,
		"selfSignedIssuers":       backup.Data.SelfSignedIssuers,
		"acmeIssuers":             backup.Data.AcmeIssuers,
		"issuedCertificates":      backup.Data.IssuedCertificates,
		"certificateDetails":      backup.Data.CertificateDetails,
		"certificateRequests":     backup.Data.CertificateRequests,
		"certificatePermissions":  backup.Data.CertificatePermissions,
		"certificateRenewals":     backup.Data.CertificateRenewals,
		"mtlsCertificates":        backup.Data.MtlsCertificates,
		"mtlsCertificateRequests": backup.Data.MtlsCertificateRequests,
	}

	for _, imp := range importFuncs {
		items := dataMap[imp.name]
		if len(items) == 0 {
			continue
		}
		result, w := imp.fn(ctx, client, items, tenantID, backup.FullBackup, mode)
		if result != nil {
			results = append(results, result)
		}
		warnings = append(warnings, w...)
	}

	s.log.Infof("imported backup: module=%s tenant=%d mode=%v results=%d warnings=%d", backupModule, tenantID, mode, len(results), len(warnings))

	return &lcmV1.ImportBackupResponse{
		Success:  true,
		Results:  results,
		Warnings: warnings,
	}, nil
}

// --- Export helpers ---

func (s *BackupService) exportLcmClients(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.LcmClient.Query()
	if !full {
		query = query.Where(lcmclient.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportLcmCa(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.LcmCa.Query()
	if !full {
		query = query.Where(lcmca.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportTenantSecrets(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.TenantSecret.Query()
	if !full {
		query = query.Where(tenantsecret.TenantIDEQ(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportIssuers(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.Issuer.Query()
	if !full {
		query = query.Where(issuer.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// SelfSignedIssuer has no TenantID — always export all
func (s *BackupService) exportSelfSignedIssuers(ctx context.Context, client *ent.Client) ([]json.RawMessage, error) {
	entities, err := client.SelfSignedIssuer.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// AcmeIssuer has no TenantID — always export all
func (s *BackupService) exportAcmeIssuers(ctx context.Context, client *ent.Client) ([]json.RawMessage, error) {
	entities, err := client.AcmeIssuer.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportIssuedCertificates(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.IssuedCertificate.Query()
	if !full {
		query = query.Where(issuedcertificate.TenantIDEQ(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// CertificateDetails has no TenantID — always export all
func (s *BackupService) exportCertificateDetails(ctx context.Context, client *ent.Client) ([]json.RawMessage, error) {
	entities, err := client.CertificateDetails.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// CertificateRequest has no TenantID — always export all
func (s *BackupService) exportCertificateRequests(ctx context.Context, client *ent.Client) ([]json.RawMessage, error) {
	entities, err := client.CertificateRequest.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportCertificatePermissions(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.CertificatePermission.Query()
	if !full {
		query = query.Where(certificatepermission.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// CertificateRenewal has no TenantID — always export all
func (s *BackupService) exportCertificateRenewals(ctx context.Context, client *ent.Client) ([]json.RawMessage, error) {
	entities, err := client.CertificateRenewal.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportMtlsCertificates(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.MtlsCertificate.Query()
	if !full {
		query = query.Where(mtlscertificate.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

func (s *BackupService) exportMtlsCertificateRequests(ctx context.Context, client *ent.Client, tenantID uint32, full bool) ([]json.RawMessage, error) {
	query := client.MtlsCertificateRequest.Query()
	if !full {
		query = query.Where(mtlscertificaterequest.TenantID(tenantID))
	}
	entities, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	return marshalEntities(entities)
}

// --- Import helpers ---

func (s *BackupService) importLcmClients(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "lcmClients", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.LcmClient
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("lcmClients: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.LcmClient.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.LcmClient.UpdateOneID(e.ID).
				SetClientID(e.ClientID).
				SetDescription(e.Description).
				SetOrganization(e.Organization).
				SetContactEmail(e.ContactEmail).
				SetMetadata(e.Metadata).
				SetNillableStatus(e.Status).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("lcmClients: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.LcmClient.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetClientID(e.ClientID).
				SetDescription(e.Description).
				SetOrganization(e.Organization).
				SetContactEmail(e.ContactEmail).
				SetMetadata(e.Metadata).
				SetNillableStatus(e.Status).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("lcmClients: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importLcmCa(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "lcmCa", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.LcmCa
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("lcmCa: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.LcmCa.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.LcmCa.UpdateOneID(e.ID).
				SetKeyPem(e.KeyPem).
				SetCertificatePem(e.CertificatePem).
				SetFingerprint(e.Fingerprint).
				SetSubject(e.Subject).
				SetSerial(e.Serial).
				SetNillableNotBefore(e.NotBefore).
				SetNillableNotAfter(e.NotAfter).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("lcmCa: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.LcmCa.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetKeyPem(e.KeyPem).
				SetCertificatePem(e.CertificatePem).
				SetFingerprint(e.Fingerprint).
				SetSubject(e.Subject).
				SetSerial(e.Serial).
				SetNillableNotBefore(e.NotBefore).
				SetNillableNotAfter(e.NotAfter).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("lcmCa: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importTenantSecrets(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "tenantSecrets", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.TenantSecret
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("tenantSecrets: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full {
			tid = e.TenantID
		}

		existing, _ := client.TenantSecret.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.TenantSecret.UpdateOneID(e.ID).
				SetSecretHash(e.SecretHash).
				SetDescription(e.Description).
				SetStatus(e.Status).
				SetNillableExpiresAt(e.ExpiresAt).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("tenantSecrets: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.TenantSecret.Create().
				SetID(e.ID).
				SetTenantID(tid).
				SetSecretHash(e.SecretHash).
				SetDescription(e.Description).
				SetStatus(e.Status).
				SetNillableExpiresAt(e.ExpiresAt).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("tenantSecrets: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importIssuers(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "issuers", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.Issuer
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("issuers: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.Issuer.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.Issuer.UpdateOneID(e.ID).
				SetName(e.Name).
				SetType(e.Type).
				SetDescription(e.Description).
				SetConfig(e.Config).
				SetClientID(e.ClientID).
				SetNillableStatus(e.Status).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("issuers: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.Issuer.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetName(e.Name).
				SetType(e.Type).
				SetDescription(e.Description).
				SetConfig(e.Config).
				SetClientID(e.ClientID).
				SetNillableStatus(e.Status).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("issuers: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// SelfSignedIssuer has no TenantID and no standard mixin fields
func (s *BackupService) importSelfSignedIssuers(ctx context.Context, client *ent.Client, items []json.RawMessage, _ uint32, _ bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "selfSignedIssuers", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.SelfSignedIssuer
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("selfSignedIssuers: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		existing, _ := client.SelfSignedIssuer.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.SelfSignedIssuer.UpdateOneID(e.ID).
				SetCommonName(e.CommonName).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetCaCommonName(e.CaCommonName).
				SetCaOrganization(e.CaOrganization).
				SetCaOrganizationalUnit(e.CaOrganizationalUnit).
				SetCaCountry(e.CaCountry).
				SetCaProvince(e.CaProvince).
				SetCaLocality(e.CaLocality).
				SetCaValidityDays(e.CaValidityDays).
				SetCaCertificatePem(e.CaCertificatePem).
				SetCaPrivateKeyPem(e.CaPrivateKeyPem).
				SetCaCertificateFingerprint(e.CaCertificateFingerprint).
				SetCaExpiresAt(e.CaExpiresAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("selfSignedIssuers: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.SelfSignedIssuer.Create().
				SetCommonName(e.CommonName).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetCaCommonName(e.CaCommonName).
				SetCaOrganization(e.CaOrganization).
				SetCaOrganizationalUnit(e.CaOrganizationalUnit).
				SetCaCountry(e.CaCountry).
				SetCaProvince(e.CaProvince).
				SetCaLocality(e.CaLocality).
				SetCaValidityDays(e.CaValidityDays).
				SetCaCertificatePem(e.CaCertificatePem).
				SetCaPrivateKeyPem(e.CaPrivateKeyPem).
				SetCaCertificateFingerprint(e.CaCertificateFingerprint).
				SetCaExpiresAt(e.CaExpiresAt).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("selfSignedIssuers: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// AcmeIssuer has no TenantID and no standard mixin fields
func (s *BackupService) importAcmeIssuers(ctx context.Context, client *ent.Client, items []json.RawMessage, _ uint32, _ bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "acmeIssuers", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.AcmeIssuer
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("acmeIssuers: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		existing, _ := client.AcmeIssuer.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.AcmeIssuer.UpdateOneID(e.ID).
				SetEmail(e.Email).
				SetEndpoint(e.Endpoint).
				SetKeyType(e.KeyType).
				SetKeySize(e.KeySize).
				SetKeyPem(e.KeyPem).
				SetMaxRetries(e.MaxRetries).
				SetBaseDelay(e.BaseDelay).
				SetChallengeType(e.ChallengeType).
				SetProviderName(e.ProviderName).
				SetProviderConfig(e.ProviderConfig).
				SetEabKid(e.EabKid).
				SetEabHmacKey(e.EabHmacKey).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("acmeIssuers: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.AcmeIssuer.Create().
				SetEmail(e.Email).
				SetEndpoint(e.Endpoint).
				SetKeyType(e.KeyType).
				SetKeySize(e.KeySize).
				SetKeyPem(e.KeyPem).
				SetMaxRetries(e.MaxRetries).
				SetBaseDelay(e.BaseDelay).
				SetChallengeType(e.ChallengeType).
				SetProviderName(e.ProviderName).
				SetProviderConfig(e.ProviderConfig).
				SetEabKid(e.EabKid).
				SetEabHmacKey(e.EabHmacKey).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("acmeIssuers: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// IssuedCertificate has string ID and non-pointer TenantID
func (s *BackupService) importIssuedCertificates(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "issuedCertificates", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.IssuedCertificate
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("issuedCertificates: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full {
			tid = e.TenantID
		}

		existing, _ := client.IssuedCertificate.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.IssuedCertificate.UpdateOneID(e.ID).
				SetClientID(e.ClientID).
				SetIssuerName(e.IssuerName).
				SetIssuerType(e.IssuerType).
				SetCommonName(e.CommonName).
				SetDomains(e.Domains).
				SetIPAddresses(e.IPAddresses).
				SetStatus(e.Status).
				SetCertPem(e.CertPem).
				SetPrivateKeyPem(e.PrivateKeyPem).
				SetServerGeneratedKey(e.ServerGeneratedKey).
				SetCaCertPem(e.CaCertPem).
				SetCsrPem(e.CsrPem).
				SetCertificateFingerprint(e.CertificateFingerprint).
				SetErrorMessage(e.ErrorMessage).
				SetKeyType(e.KeyType).
				SetKeySize(e.KeySize).
				SetAutoRenewEnabled(e.AutoRenewEnabled).
				SetAutoRenewDaysBeforeExpiry(e.AutoRenewDaysBeforeExpiry).
				SetAutoRenewMaxAttempts(e.AutoRenewMaxAttempts).
				SetAutoRenewRetryIntervalSeconds(e.AutoRenewRetryIntervalSeconds).
				SetLastRenewalAt(e.LastRenewalAt).
				SetRenewalAttempts(e.RenewalAttempts).
				SetExpiresAt(e.ExpiresAt).
				SetRevokedAt(e.RevokedAt).
				SetRevokedReason(e.RevokedReason).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("issuedCertificates: update %s: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.IssuedCertificate.Create().
				SetID(e.ID).
				SetTenantID(tid).
				SetClientID(e.ClientID).
				SetIssuerName(e.IssuerName).
				SetIssuerType(e.IssuerType).
				SetCommonName(e.CommonName).
				SetDomains(e.Domains).
				SetIPAddresses(e.IPAddresses).
				SetStatus(e.Status).
				SetCertPem(e.CertPem).
				SetPrivateKeyPem(e.PrivateKeyPem).
				SetServerGeneratedKey(e.ServerGeneratedKey).
				SetCaCertPem(e.CaCertPem).
				SetCsrPem(e.CsrPem).
				SetCertificateFingerprint(e.CertificateFingerprint).
				SetErrorMessage(e.ErrorMessage).
				SetKeyType(e.KeyType).
				SetKeySize(e.KeySize).
				SetAutoRenewEnabled(e.AutoRenewEnabled).
				SetAutoRenewDaysBeforeExpiry(e.AutoRenewDaysBeforeExpiry).
				SetAutoRenewMaxAttempts(e.AutoRenewMaxAttempts).
				SetAutoRenewRetryIntervalSeconds(e.AutoRenewRetryIntervalSeconds).
				SetLastRenewalAt(e.LastRenewalAt).
				SetRenewalAttempts(e.RenewalAttempts).
				SetExpiresAt(e.ExpiresAt).
				SetRevokedAt(e.RevokedAt).
				SetRevokedReason(e.RevokedReason).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("issuedCertificates: create %s: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// CertificateDetails has no TenantID
func (s *BackupService) importCertificateDetails(ctx context.Context, client *ent.Client, items []json.RawMessage, _ uint32, _ bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "certificateDetails", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.CertificateDetails
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("certificateDetails: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		existing, _ := client.CertificateDetails.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.CertificateDetails.UpdateOneID(e.ID).
				SetCertificateID(e.CertificateID).
				SetSerialNumber(e.SerialNumber).
				SetIPAddresses(e.IPAddresses).
				SetSubjectCommonName(e.SubjectCommonName).
				SetSubjectOrganization(e.SubjectOrganization).
				SetSubjectOrganizationalUnit(e.SubjectOrganizationalUnit).
				SetSubjectCountry(e.SubjectCountry).
				SetSubjectState(e.SubjectState).
				SetSubjectLocality(e.SubjectLocality).
				SetIssuerCommonName(e.IssuerCommonName).
				SetIssuerOrganization(e.IssuerOrganization).
				SetIssuerCountry(e.IssuerCountry).
				SetIssuerType(e.IssuerType).
				SetSignatureAlgorithm(e.SignatureAlgorithm).
				SetPublicKeyAlgorithm(e.PublicKeyAlgorithm).
				SetKeySize(e.KeySize).
				SetDNSNames(e.DNSNames).
				SetEmailAddresses(e.EmailAddresses).
				SetNotBefore(e.NotBefore).
				SetNotAfter(e.NotAfter).
				SetIsCa(e.IsCa).
				SetKeyUsage(e.KeyUsage).
				SetExtendedKeyUsage(e.ExtendedKeyUsage).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateDetails: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.CertificateDetails.Create().
				SetID(e.ID).
				SetCertificateID(e.CertificateID).
				SetSerialNumber(e.SerialNumber).
				SetIPAddresses(e.IPAddresses).
				SetSubjectCommonName(e.SubjectCommonName).
				SetSubjectOrganization(e.SubjectOrganization).
				SetSubjectOrganizationalUnit(e.SubjectOrganizationalUnit).
				SetSubjectCountry(e.SubjectCountry).
				SetSubjectState(e.SubjectState).
				SetSubjectLocality(e.SubjectLocality).
				SetIssuerCommonName(e.IssuerCommonName).
				SetIssuerOrganization(e.IssuerOrganization).
				SetIssuerCountry(e.IssuerCountry).
				SetIssuerType(e.IssuerType).
				SetSignatureAlgorithm(e.SignatureAlgorithm).
				SetPublicKeyAlgorithm(e.PublicKeyAlgorithm).
				SetKeySize(e.KeySize).
				SetDNSNames(e.DNSNames).
				SetEmailAddresses(e.EmailAddresses).
				SetNotBefore(e.NotBefore).
				SetNotAfter(e.NotAfter).
				SetIsCa(e.IsCa).
				SetKeyUsage(e.KeyUsage).
				SetExtendedKeyUsage(e.ExtendedKeyUsage).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateDetails: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// CertificateRequest has no TenantID and no standard mixin fields
func (s *BackupService) importCertificateRequests(ctx context.Context, client *ent.Client, items []json.RawMessage, _ uint32, _ bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "certificateRequests", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.CertificateRequest
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("certificateRequests: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		existing, _ := client.CertificateRequest.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.CertificateRequest.UpdateOneID(e.ID).
				SetRequestID(e.RequestID).
				SetClientID(e.ClientID).
				SetIssuerName(e.IssuerName).
				SetHostname(e.Hostname).
				SetPublicKey(e.PublicKey).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetMetadata(e.Metadata).
				SetStatus(e.Status).
				SetCertificate(e.Certificate).
				SetExpiresAt(e.ExpiresAt).
				SetRevokedAt(e.RevokedAt).
				SetRevokedBy(e.RevokedBy).
				SetRevokedReason(e.RevokedReason).
				SetApprovedBy(e.ApprovedBy).
				SetApprovedAt(e.ApprovedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateRequests: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.CertificateRequest.Create().
				SetRequestID(e.RequestID).
				SetClientID(e.ClientID).
				SetIssuerName(e.IssuerName).
				SetHostname(e.Hostname).
				SetPublicKey(e.PublicKey).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetMetadata(e.Metadata).
				SetStatus(e.Status).
				SetCertificate(e.Certificate).
				SetExpiresAt(e.ExpiresAt).
				SetRevokedAt(e.RevokedAt).
				SetRevokedBy(e.RevokedBy).
				SetRevokedReason(e.RevokedReason).
				SetApprovedBy(e.ApprovedBy).
				SetApprovedAt(e.ApprovedAt).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateRequests: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// CertificatePermission has TenantID *uint32 but no standard mixin (uses CreatedAt/UpdatedAt)
func (s *BackupService) importCertificatePermissions(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "certificatePermissions", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.CertificatePermission
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("certificatePermissions: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.CertificatePermission.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.CertificatePermission.UpdateOneID(e.ID).
				SetCertificateID(e.CertificateID).
				SetGranteeID(e.GranteeID).
				SetPermissionType(e.PermissionType).
				SetGrantedBy(e.GrantedBy).
				SetNillableExpiresAt(e.ExpiresAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificatePermissions: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.CertificatePermission.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetCertificateID(e.CertificateID).
				SetGranteeID(e.GranteeID).
				SetPermissionType(e.PermissionType).
				SetGrantedBy(e.GrantedBy).
				SetNillableExpiresAt(e.ExpiresAt).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificatePermissions: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

// CertificateRenewal has no TenantID and no standard mixin fields
func (s *BackupService) importCertificateRenewals(ctx context.Context, client *ent.Client, items []json.RawMessage, _ uint32, _ bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "certificateRenewals", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.CertificateRenewal
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("certificateRenewals: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		existing, _ := client.CertificateRenewal.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.CertificateRenewal.UpdateOneID(e.ID).
				SetCertificateID(e.CertificateID).
				SetClientID(e.ClientID).
				SetStatus(e.Status).
				SetScheduledAt(e.ScheduledAt).
				SetStartedAt(e.StartedAt).
				SetCompletedAt(e.CompletedAt).
				SetAttemptNumber(e.AttemptNumber).
				SetMaxAttempts(e.MaxAttempts).
				SetErrorMessage(e.ErrorMessage).
				SetWorkerID(e.WorkerID).
				SetLockedAt(e.LockedAt).
				SetLockExpiresAt(e.LockExpiresAt).
				SetRenewalConfig(e.RenewalConfig).
				SetIssuerName(e.IssuerName).
				SetDomains(e.Domains).
				SetOriginalExpiresAt(e.OriginalExpiresAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateRenewals: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.CertificateRenewal.Create().
				SetCertificateID(e.CertificateID).
				SetClientID(e.ClientID).
				SetStatus(e.Status).
				SetScheduledAt(e.ScheduledAt).
				SetStartedAt(e.StartedAt).
				SetCompletedAt(e.CompletedAt).
				SetAttemptNumber(e.AttemptNumber).
				SetMaxAttempts(e.MaxAttempts).
				SetErrorMessage(e.ErrorMessage).
				SetWorkerID(e.WorkerID).
				SetLockedAt(e.LockedAt).
				SetLockExpiresAt(e.LockExpiresAt).
				SetRenewalConfig(e.RenewalConfig).
				SetIssuerName(e.IssuerName).
				SetDomains(e.Domains).
				SetOriginalExpiresAt(e.OriginalExpiresAt).
				SetCreatedAt(e.CreatedAt).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("certificateRenewals: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importMtlsCertificates(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "mtlsCertificates", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.MtlsCertificate
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("mtlsCertificates: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.MtlsCertificate.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.MtlsCertificate.UpdateOneID(e.ID).
				SetSerialNumber(e.SerialNumber).
				SetClientID(e.ClientID).
				SetCommonName(e.CommonName).
				SetSubjectDn(e.SubjectDn).
				SetIssuerDn(e.IssuerDn).
				SetIssuerName(e.IssuerName).
				SetFingerprintSha256(e.FingerprintSha256).
				SetFingerprintSha1(e.FingerprintSha1).
				SetPublicKeyAlgorithm(e.PublicKeyAlgorithm).
				SetNillablePublicKeySize(e.PublicKeySize).
				SetSignatureAlgorithm(e.SignatureAlgorithm).
				SetCertificatePem(e.CertificatePem).
				SetPublicKeyPem(e.PublicKeyPem).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("mtlsCertificates: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.MtlsCertificate.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetSerialNumber(e.SerialNumber).
				SetClientID(e.ClientID).
				SetCommonName(e.CommonName).
				SetSubjectDn(e.SubjectDn).
				SetIssuerDn(e.IssuerDn).
				SetIssuerName(e.IssuerName).
				SetFingerprintSha256(e.FingerprintSha256).
				SetFingerprintSha1(e.FingerprintSha1).
				SetPublicKeyAlgorithm(e.PublicKeyAlgorithm).
				SetNillablePublicKeySize(e.PublicKeySize).
				SetSignatureAlgorithm(e.SignatureAlgorithm).
				SetCertificatePem(e.CertificatePem).
				SetPublicKeyPem(e.PublicKeyPem).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("mtlsCertificates: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}

func (s *BackupService) importMtlsCertificateRequests(ctx context.Context, client *ent.Client, items []json.RawMessage, tenantID uint32, full bool, mode lcmV1.RestoreMode) (*lcmV1.EntityImportResult, []string) {
	result := &lcmV1.EntityImportResult{EntityType: "mtlsCertificateRequests", Total: int64(len(items))}
	var warnings []string

	for _, raw := range items {
		var e ent.MtlsCertificateRequest
		if err := json.Unmarshal(raw, &e); err != nil {
			warnings = append(warnings, fmt.Sprintf("mtlsCertificateRequests: unmarshal error: %v", err))
			result.Failed++
			continue
		}

		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, _ := client.MtlsCertificateRequest.Get(ctx, e.ID)
		if existing != nil {
			if mode == lcmV1.RestoreMode_RESTORE_MODE_SKIP {
				result.Skipped++
				continue
			}
			_, err := client.MtlsCertificateRequest.UpdateOneID(e.ID).
				SetRequestID(e.RequestID).
				SetClientID(e.ClientID).
				SetCommonName(e.CommonName).
				SetCsrPem(e.CsrPem).
				SetPublicKey(e.PublicKey).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetIssuerName(e.IssuerName).
				SetNillableCertType(e.CertType).
				SetNillableStatus(e.Status).
				SetNillableValidityDays(e.ValidityDays).
				SetRejectReason(e.RejectReason).
				SetMetadata(e.Metadata).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("mtlsCertificateRequests: update %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Updated++
		} else {
			_, err := client.MtlsCertificateRequest.Create().
				SetID(e.ID).
				SetNillableTenantID(&tid).
				SetRequestID(e.RequestID).
				SetClientID(e.ClientID).
				SetCommonName(e.CommonName).
				SetCsrPem(e.CsrPem).
				SetPublicKey(e.PublicKey).
				SetDNSNames(e.DNSNames).
				SetIPAddresses(e.IPAddresses).
				SetIssuerName(e.IssuerName).
				SetNillableCertType(e.CertType).
				SetNillableStatus(e.Status).
				SetNillableValidityDays(e.ValidityDays).
				SetRejectReason(e.RejectReason).
				SetMetadata(e.Metadata).
				SetNillableCreateBy(e.CreateBy).
				SetNillableUpdateBy(e.UpdateBy).
				SetNillableCreateTime(e.CreateTime).
				Save(ctx)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("mtlsCertificateRequests: create %d: %v", e.ID, err))
				result.Failed++
				continue
			}
			result.Created++
		}
	}

	return result, warnings
}
