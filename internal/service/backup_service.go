package service

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-common/backup"
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
	backupModule        = "lcm"
	backupSchemaVersion = 1
)

// Migrations registry — add entries here when schema changes.
var migrations = backup.NewMigrationRegistry(backupModule)

// Register migrations in init. Example for future use:
//
//	func init() {
//	    migrations.Register(1, func(entities map[string]json.RawMessage) error {
//	        return backup.MigrateAddField(entities, "issuers", "newField", "")
//	    })
//	}

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

// ExportBackup exports all LCM entities as a gzipped archive.
func (s *BackupService) ExportBackup(ctx context.Context, req *lcmV1.ExportBackupRequest) (*lcmV1.ExportBackupResponse, error) {
	tenantID := grpcx.GetTenantIDFromContext(ctx)
	full := false

	if grpcx.IsPlatformAdmin(ctx) && req.TenantId != nil && *req.TenantId == 0 {
		full = true
		tenantID = 0
	} else if req.TenantId != nil && *req.TenantId != 0 && grpcx.IsPlatformAdmin(ctx) {
		tenantID = *req.TenantId
	}

	client := s.entClient.Client()
	a := backup.NewArchive(backupModule, backupSchemaVersion, tenantID, full)

	// Export lcmClients
	lcmClientsQuery := client.LcmClient.Query()
	if !full {
		lcmClientsQuery = lcmClientsQuery.Where(lcmclient.TenantID(tenantID))
	}
	lcmClients, err := lcmClientsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export lcmClients: %w", err)
	}
	if err := backup.SetEntities(a, "lcmClients", lcmClients); err != nil {
		return nil, fmt.Errorf("set lcmClients: %w", err)
	}

	// Export lcmCa
	lcmCaQuery := client.LcmCa.Query()
	if !full {
		lcmCaQuery = lcmCaQuery.Where(lcmca.TenantID(tenantID))
	}
	lcmCas, err := lcmCaQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export lcmCa: %w", err)
	}
	if err := backup.SetEntities(a, "lcmCa", lcmCas); err != nil {
		return nil, fmt.Errorf("set lcmCa: %w", err)
	}

	// Export tenantSecrets
	tenantSecretsQuery := client.TenantSecret.Query()
	if !full {
		tenantSecretsQuery = tenantSecretsQuery.Where(tenantsecret.TenantIDEQ(tenantID))
	}
	tenantSecrets, err := tenantSecretsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export tenantSecrets: %w", err)
	}
	if err := backup.SetEntities(a, "tenantSecrets", tenantSecrets); err != nil {
		return nil, fmt.Errorf("set tenantSecrets: %w", err)
	}

	// Export issuers
	issuersQuery := client.Issuer.Query()
	if !full {
		issuersQuery = issuersQuery.Where(issuer.TenantID(tenantID))
	}
	issuers, err := issuersQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export issuers: %w", err)
	}
	if err := backup.SetEntities(a, "issuers", issuers); err != nil {
		return nil, fmt.Errorf("set issuers: %w", err)
	}

	// Export selfSignedIssuers (no TenantID — always export all)
	selfSignedIssuers, err := client.SelfSignedIssuer.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export selfSignedIssuers: %w", err)
	}
	if err := backup.SetEntities(a, "selfSignedIssuers", selfSignedIssuers); err != nil {
		return nil, fmt.Errorf("set selfSignedIssuers: %w", err)
	}

	// Export acmeIssuers (no TenantID — always export all)
	acmeIssuers, err := client.AcmeIssuer.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export acmeIssuers: %w", err)
	}
	if err := backup.SetEntities(a, "acmeIssuers", acmeIssuers); err != nil {
		return nil, fmt.Errorf("set acmeIssuers: %w", err)
	}

	// Export issuedCertificates
	issuedCertsQuery := client.IssuedCertificate.Query()
	if !full {
		issuedCertsQuery = issuedCertsQuery.Where(issuedcertificate.TenantIDEQ(tenantID))
	}
	issuedCertificates, err := issuedCertsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export issuedCertificates: %w", err)
	}
	if err := backup.SetEntities(a, "issuedCertificates", issuedCertificates); err != nil {
		return nil, fmt.Errorf("set issuedCertificates: %w", err)
	}

	// Export certificateDetails (no TenantID — always export all)
	certificateDetails, err := client.CertificateDetails.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export certificateDetails: %w", err)
	}
	if err := backup.SetEntities(a, "certificateDetails", certificateDetails); err != nil {
		return nil, fmt.Errorf("set certificateDetails: %w", err)
	}

	// Export certificateRequests (no TenantID — always export all)
	certificateRequests, err := client.CertificateRequest.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export certificateRequests: %w", err)
	}
	if err := backup.SetEntities(a, "certificateRequests", certificateRequests); err != nil {
		return nil, fmt.Errorf("set certificateRequests: %w", err)
	}

	// Export certificatePermissions
	certPermsQuery := client.CertificatePermission.Query()
	if !full {
		certPermsQuery = certPermsQuery.Where(certificatepermission.TenantID(tenantID))
	}
	certificatePermissions, err := certPermsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export certificatePermissions: %w", err)
	}
	if err := backup.SetEntities(a, "certificatePermissions", certificatePermissions); err != nil {
		return nil, fmt.Errorf("set certificatePermissions: %w", err)
	}

	// Export certificateRenewals (no TenantID — always export all)
	certificateRenewals, err := client.CertificateRenewal.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export certificateRenewals: %w", err)
	}
	if err := backup.SetEntities(a, "certificateRenewals", certificateRenewals); err != nil {
		return nil, fmt.Errorf("set certificateRenewals: %w", err)
	}

	// Export mtlsCertificates
	mtlsCertsQuery := client.MtlsCertificate.Query()
	if !full {
		mtlsCertsQuery = mtlsCertsQuery.Where(mtlscertificate.TenantID(tenantID))
	}
	mtlsCertificates, err := mtlsCertsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export mtlsCertificates: %w", err)
	}
	if err := backup.SetEntities(a, "mtlsCertificates", mtlsCertificates); err != nil {
		return nil, fmt.Errorf("set mtlsCertificates: %w", err)
	}

	// Export mtlsCertificateRequests
	mtlsReqsQuery := client.MtlsCertificateRequest.Query()
	if !full {
		mtlsReqsQuery = mtlsReqsQuery.Where(mtlscertificaterequest.TenantID(tenantID))
	}
	mtlsCertificateRequests, err := mtlsReqsQuery.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("export mtlsCertificateRequests: %w", err)
	}
	if err := backup.SetEntities(a, "mtlsCertificateRequests", mtlsCertificateRequests); err != nil {
		return nil, fmt.Errorf("set mtlsCertificateRequests: %w", err)
	}

	// Pack (JSON + gzip)
	data, err := backup.Pack(a)
	if err != nil {
		return nil, fmt.Errorf("pack backup: %w", err)
	}

	s.log.Infof("exported backup: module=%s tenant=%d full=%v entities=%v", backupModule, tenantID, full, a.Manifest.EntityCounts)

	return &lcmV1.ExportBackupResponse{
		Data:          data,
		Module:        backupModule,
		Version:       fmt.Sprintf("%d", backupSchemaVersion),
		ExportedAt:    timestamppb.New(a.Manifest.ExportedAt),
		TenantId:      tenantID,
		EntityCounts:  a.Manifest.EntityCounts,
		SchemaVersion: int32(backupSchemaVersion),
	}, nil
}

// ImportBackup restores LCM entities from a gzipped archive.
func (s *BackupService) ImportBackup(ctx context.Context, req *lcmV1.ImportBackupRequest) (*lcmV1.ImportBackupResponse, error) {
	tenantID := grpcx.GetTenantIDFromContext(ctx)
	isPlatformAdmin := grpcx.IsPlatformAdmin(ctx)
	mode := mapLcmRestoreMode(req.GetMode())

	// Unpack
	a, err := backup.Unpack(req.GetData())
	if err != nil {
		return nil, fmt.Errorf("unpack backup: %w", err)
	}

	// Validate
	if err := backup.Validate(a, backupModule, backupSchemaVersion); err != nil {
		return nil, err
	}

	// Full backups require platform admin
	if a.Manifest.FullBackup && !isPlatformAdmin {
		return nil, fmt.Errorf("only platform admins can restore full backups")
	}

	// Run migrations if needed
	sourceVersion := a.Manifest.SchemaVersion
	applied, err := migrations.RunMigrations(a, backupSchemaVersion)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Determine restore tenant
	if !isPlatformAdmin || !a.Manifest.FullBackup {
		tenantID = grpcx.GetTenantIDFromContext(ctx)
	} else {
		tenantID = 0
	}

	client := s.entClient.Client()
	result := backup.NewRestoreResult(sourceVersion, backupSchemaVersion, applied)

	// Import in FK dependency order
	s.importLcmClients(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importLcmCa(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importTenantSecrets(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importIssuers(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importSelfSignedIssuers(ctx, client, a, mode, result)
	s.importAcmeIssuers(ctx, client, a, mode, result)
	s.importIssuedCertificates(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importCertificateDetails(ctx, client, a, mode, result)
	s.importCertificateRequests(ctx, client, a, mode, result)
	s.importCertificatePermissions(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importCertificateRenewals(ctx, client, a, mode, result)
	s.importMtlsCertificates(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)
	s.importMtlsCertificateRequests(ctx, client, a, tenantID, a.Manifest.FullBackup, mode, result)

	s.log.Infof("imported backup: module=%s tenant=%d mode=%v migrations=%d results=%d",
		backupModule, tenantID, mode, applied, len(result.Results))

	// Convert to proto response
	protoResults := make([]*lcmV1.EntityImportResult, len(result.Results))
	for i, r := range result.Results {
		protoResults[i] = &lcmV1.EntityImportResult{
			EntityType: r.EntityType,
			Total:      r.Total,
			Created:    r.Created,
			Updated:    r.Updated,
			Skipped:    r.Skipped,
			Failed:     r.Failed,
		}
	}

	return &lcmV1.ImportBackupResponse{
		Success:           result.Success,
		Results:           protoResults,
		Warnings:          result.Warnings,
		SourceVersion:     int32(result.SourceVersion),
		TargetVersion:     int32(result.TargetVersion),
		MigrationsApplied: int32(result.MigrationsApplied),
	}, nil
}

func mapLcmRestoreMode(m lcmV1.RestoreMode) backup.RestoreMode {
	if m == lcmV1.RestoreMode_RESTORE_MODE_OVERWRITE {
		return backup.RestoreModeOverwrite
	}
	return backup.RestoreModeSkip
}

// --- Import helpers ---

func (s *BackupService) importLcmClients(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.LcmClient](a, "lcmClients")
	if err != nil {
		result.AddWarning(fmt.Sprintf("lcmClients: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "lcmClients", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.LcmClient.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("lcmClients: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("lcmClients: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("lcmClients: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importLcmCa(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.LcmCa](a, "lcmCa")
	if err != nil {
		result.AddWarning(fmt.Sprintf("lcmCa: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "lcmCa", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.LcmCa.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("lcmCa: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("lcmCa: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("lcmCa: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importTenantSecrets(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.TenantSecret](a, "tenantSecrets")
	if err != nil {
		result.AddWarning(fmt.Sprintf("tenantSecrets: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "tenantSecrets", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full {
			tid = e.TenantID
		}

		existing, getErr := client.TenantSecret.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("tenantSecrets: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("tenantSecrets: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("tenantSecrets: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importIssuers(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.Issuer](a, "issuers")
	if err != nil {
		result.AddWarning(fmt.Sprintf("issuers: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "issuers", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.Issuer.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("issuers: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("issuers: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("issuers: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// SelfSignedIssuer has no TenantID
func (s *BackupService) importSelfSignedIssuers(ctx context.Context, client *ent.Client, a *backup.Archive, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.SelfSignedIssuer](a, "selfSignedIssuers")
	if err != nil {
		result.AddWarning(fmt.Sprintf("selfSignedIssuers: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "selfSignedIssuers", Total: int64(len(entities))}

	for _, e := range entities {
		existing, getErr := client.SelfSignedIssuer.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("selfSignedIssuers: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("selfSignedIssuers: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("selfSignedIssuers: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// AcmeIssuer has no TenantID
func (s *BackupService) importAcmeIssuers(ctx context.Context, client *ent.Client, a *backup.Archive, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.AcmeIssuer](a, "acmeIssuers")
	if err != nil {
		result.AddWarning(fmt.Sprintf("acmeIssuers: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "acmeIssuers", Total: int64(len(entities))}

	for _, e := range entities {
		existing, getErr := client.AcmeIssuer.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("acmeIssuers: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("acmeIssuers: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("acmeIssuers: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// IssuedCertificate has string ID and non-pointer TenantID
func (s *BackupService) importIssuedCertificates(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.IssuedCertificate](a, "issuedCertificates")
	if err != nil {
		result.AddWarning(fmt.Sprintf("issuedCertificates: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "issuedCertificates", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full {
			tid = e.TenantID
		}

		existing, getErr := client.IssuedCertificate.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("issuedCertificates: lookup %s: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("issuedCertificates: update %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("issuedCertificates: create %s: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// CertificateDetails has no TenantID
func (s *BackupService) importCertificateDetails(ctx context.Context, client *ent.Client, a *backup.Archive, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.CertificateDetails](a, "certificateDetails")
	if err != nil {
		result.AddWarning(fmt.Sprintf("certificateDetails: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "certificateDetails", Total: int64(len(entities))}

	for _, e := range entities {
		existing, getErr := client.CertificateDetails.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("certificateDetails: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("certificateDetails: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("certificateDetails: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// CertificateRequest has no TenantID
func (s *BackupService) importCertificateRequests(ctx context.Context, client *ent.Client, a *backup.Archive, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.CertificateRequest](a, "certificateRequests")
	if err != nil {
		result.AddWarning(fmt.Sprintf("certificateRequests: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "certificateRequests", Total: int64(len(entities))}

	for _, e := range entities {
		existing, getErr := client.CertificateRequest.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("certificateRequests: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("certificateRequests: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("certificateRequests: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importCertificatePermissions(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.CertificatePermission](a, "certificatePermissions")
	if err != nil {
		result.AddWarning(fmt.Sprintf("certificatePermissions: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "certificatePermissions", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.CertificatePermission.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("certificatePermissions: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("certificatePermissions: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("certificatePermissions: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

// CertificateRenewal has no TenantID
func (s *BackupService) importCertificateRenewals(ctx context.Context, client *ent.Client, a *backup.Archive, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.CertificateRenewal](a, "certificateRenewals")
	if err != nil {
		result.AddWarning(fmt.Sprintf("certificateRenewals: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "certificateRenewals", Total: int64(len(entities))}

	for _, e := range entities {
		existing, getErr := client.CertificateRenewal.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("certificateRenewals: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("certificateRenewals: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("certificateRenewals: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importMtlsCertificates(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.MtlsCertificate](a, "mtlsCertificates")
	if err != nil {
		result.AddWarning(fmt.Sprintf("mtlsCertificates: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "mtlsCertificates", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.MtlsCertificate.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("mtlsCertificates: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("mtlsCertificates: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("mtlsCertificates: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}

func (s *BackupService) importMtlsCertificateRequests(ctx context.Context, client *ent.Client, a *backup.Archive, tenantID uint32, full bool, mode backup.RestoreMode, result *backup.RestoreResult) {
	entities, err := backup.GetEntities[ent.MtlsCertificateRequest](a, "mtlsCertificateRequests")
	if err != nil {
		result.AddWarning(fmt.Sprintf("mtlsCertificateRequests: unmarshal error: %v", err))
		return
	}
	if len(entities) == 0 {
		return
	}

	er := backup.EntityResult{EntityType: "mtlsCertificateRequests", Total: int64(len(entities))}

	for _, e := range entities {
		tid := tenantID
		if full && e.TenantID != nil {
			tid = *e.TenantID
		}

		existing, getErr := client.MtlsCertificateRequest.Get(ctx, e.ID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			result.AddWarning(fmt.Sprintf("mtlsCertificateRequests: lookup %d: %v", e.ID, getErr))
			er.Failed++
			continue
		}
		if existing != nil {
			if mode == backup.RestoreModeSkip {
				er.Skipped++
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
				result.AddWarning(fmt.Sprintf("mtlsCertificateRequests: update %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Updated++
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
				result.AddWarning(fmt.Sprintf("mtlsCertificateRequests: create %d: %v", e.ID, err))
				er.Failed++
				continue
			}
			er.Created++
		}
	}

	result.AddResult(er)
}
