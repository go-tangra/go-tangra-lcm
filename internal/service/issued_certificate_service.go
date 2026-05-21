package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	lcmClient "github.com/go-tangra/go-tangra-lcm/internal/client"
	"github.com/go-tangra/go-tangra-lcm/internal/data"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/certificaterenewal"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/issuedcertificate"
	"github.com/go-tangra/go-tangra-lcm/pkg/client"
)

// IssuedCertificateService implements the LcmIssuedCertificateService gRPC service
type IssuedCertificateService struct {
	lcmV1.UnimplementedLcmIssuedCertificateServiceServer

	log            *log.Helper
	issuedCertRepo *data.IssuedCertificateRepo
	clientRepo     *data.LcmClientRepo
	mtlsCertRepo   *data.MtlsCertificateRepo
	renewalRepo    *data.CertificateRenewalRepo
	deployerClient *lcmClient.DeployerClient
}

// NewIssuedCertificateService creates a new IssuedCertificateService
func NewIssuedCertificateService(
	ctx *bootstrap.Context,
	issuedCertRepo *data.IssuedCertificateRepo,
	clientRepo *data.LcmClientRepo,
	mtlsCertRepo *data.MtlsCertificateRepo,
	renewalRepo *data.CertificateRenewalRepo,
	deployerClient *lcmClient.DeployerClient,
) *IssuedCertificateService {
	return &IssuedCertificateService{
		log:            ctx.NewLoggerHelper("lcm/service/issued-certificate"),
		issuedCertRepo: issuedCertRepo,
		clientRepo:     clientRepo,
		mtlsCertRepo:   mtlsCertRepo,
		renewalRepo:    renewalRepo,
		deployerClient: deployerClient,
	}
}

// getClientInfo extracts the tenant ID and client ID from the authenticated client
func (s *IssuedCertificateService) getClientInfo(ctx context.Context) (uint32, string, error) {
	// If request is proxied from admin-service, use tenant ID and username from metadata
	if client.IsProxiedRequest(ctx) {
		tenantID := client.GetTenantID(ctx)
		clientID := client.GetClientID(ctx)
		s.log.Infof("Using tenant ID from metadata: %d (user: %s)", tenantID, clientID)
		return tenantID, clientID, nil
	}

	// Get CN from mTLS certificate
	certCN := client.GetClientID(ctx)
	if certCN == "" {
		return 0, "", lcmV1.ErrorUnauthorized("client authentication required")
	}

	// Try to find the actual client_id by looking up the CN in mtls_certificates
	clientID := certCN
	if s.mtlsCertRepo != nil {
		actualClientID, err := s.mtlsCertRepo.GetClientIDByCommonName(ctx, certCN)
		if err != nil {
			s.log.Errorf("Failed to lookup client_id by CN: %v", err)
		} else if actualClientID != "" {
			clientID = actualClientID
			s.log.Infof("Resolved CN '%s' to client_id '%s'", certCN, clientID)
		}
	}

	// First try to find client with tenant_id = 0 (platform-level clients)
	lcmClient, err := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", lcmV1.ErrorInternalServerError("failed to lookup client")
	}

	if lcmClient != nil {
		var tenantID uint32
		if lcmClient.TenantID != nil {
			tenantID = *lcmClient.TenantID
			client.SetTenantIDInPlace(ctx, tenantID)
		}
		return tenantID, clientID, nil
	}

	// If not found at platform level, search across all tenants
	allClients, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		s.log.Errorf("Failed to lookup client: %v", err)
		return 0, "", lcmV1.ErrorInternalServerError("failed to lookup client")
	}
	if allClients == nil {
		return 0, "", lcmV1.ErrorNotFound("client not registered")
	}

	var tenantID uint32
	if allClients.TenantID != nil {
		tenantID = *allClients.TenantID
		client.SetTenantIDInPlace(ctx, tenantID)
	}
	return tenantID, clientID, nil
}

// ListIssuedCertificates lists issued certificates with optional filters
func (s *IssuedCertificateService) ListIssuedCertificates(ctx context.Context, req *lcmV1.ListIssuedCertificatesRequest) (*lcmV1.ListIssuedCertificatesResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Build filter
	filter := &data.ListFilter{
		IssuerName: req.GetIssuerName(),
		Page:       req.GetPage(),
		PageSize:   req.GetPageSize(),
	}

	// Set default pagination
	if filter.PageSize == 0 {
		filter.PageSize = 20
	}
	if filter.Page == 0 {
		filter.Page = 1
	}

	// Admin clients (tenant_id=0) can query all; others only their own
	if tenantID != 0 {
		filter.TenantID = &tenantID
	}

	// Map proto status to database status
	if req.Status != nil && *req.Status != lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_UNSPECIFIED {
		dbStatus := mapIssuedCertProtoStatusToDB(*req.Status)
		filter.Status = &dbStatus
	}

	// Auto-renew filter
	if req.AutoRenewEnabled != nil {
		filter.AutoRenewEnabled = req.AutoRenewEnabled
	}

	// Query the database
	certs, total, err := s.issuedCertRepo.List(ctx, filter)
	if err != nil {
		s.log.Errorf("Failed to list issued certificates: %v", err)
		return nil, err
	}

	response := &lcmV1.ListIssuedCertificatesResponse{
		Certificates: make([]*lcmV1.IssuedCertificateInfo, 0, len(certs)),
		Total:        total,
	}

	for _, cert := range certs {
		response.Certificates = append(response.Certificates, mapIssuedCertToProto(cert))
	}

	return response, nil
}

// GetIssuedCertificate gets a single issued certificate by ID
func (s *IssuedCertificateService) GetIssuedCertificate(ctx context.Context, req *lcmV1.GetIssuedCertificateRequest) (*lcmV1.GetIssuedCertificateResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Verify tenant access
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	resp := &lcmV1.GetIssuedCertificateResponse{
		Certificate: mapIssuedCertToProto(cert),
	}

	// Include certificate PEM data
	if cert.CertPem != "" {
		resp.CertificatePem = &cert.CertPem
	}
	if cert.CaCertPem != "" {
		resp.CaCertificatePem = &cert.CaCertPem
	}

	serverGenKey := cert.ServerGeneratedKey
	resp.ServerGeneratedKey = &serverGenKey

	// Include private key only if requested and server generated it
	if req.IncludePrivateKey != nil && *req.IncludePrivateKey && cert.ServerGeneratedKey && cert.PrivateKeyPem != "" {
		resp.PrivateKeyPem = &cert.PrivateKeyPem
	}

	return resp, nil
}

// ForceRenewCertificate triggers an immediate renewal for an issued certificate
func (s *IssuedCertificateService) ForceRenewCertificate(ctx context.Context, req *lcmV1.ForceRenewCertificateRequest) (*lcmV1.ForceRenewCertificateResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Look up the certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Verify tenant access
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Only allow renewal for ISSUED or EXPIRED certificates
	if cert.Status != issuedcertificate.StatusIssued && cert.Status != issuedcertificate.StatusExpired {
		return nil, lcmV1.ErrorBadRequest("certificate must be in ISSUED or EXPIRED status to renew")
	}

	// Check if there's already a pending/processing renewal
	existing, err := s.renewalRepo.GetPendingByCertificateID(ctx, cert.ID)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.Status == certificaterenewal.StatusProcessing {
		return nil, lcmV1.ErrorBadRequest("renewal already in progress for this certificate")
	}

	// Cancel any existing pending renewal
	if existing != nil {
		if cancelErr := s.renewalRepo.Cancel(ctx, existing.ID); cancelErr != nil {
			s.log.Errorf("Failed to cancel existing renewal %d: %v", existing.ID, cancelErr)
		}
	}

	// Create a new renewal job scheduled immediately
	renewal := &ent.CertificateRenewal{
		CertificateID:     cert.ID,
		ClientID:          cert.ClientID,
		IssuerName:        cert.IssuerName,
		Domains:           cert.Domains,
		OriginalExpiresAt: cert.ExpiresAt,
		ScheduledAt:       time.Now(),
		MaxAttempts:       3,
	}

	created, err := s.renewalRepo.Create(ctx, renewal)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Force renewal scheduled for certificate %s (renewal ID: %d)", cert.ID, created.ID)

	return &lcmV1.ForceRenewCertificateResponse{
		RenewalId: fmt.Sprintf("%d", created.ID),
		Message:   "Renewal scheduled successfully",
	}, nil
}

// UpdateIssuedCertificate updates an issued certificate's settings (e.g. auto-renew)
func (s *IssuedCertificateService) UpdateIssuedCertificate(ctx context.Context, req *lcmV1.UpdateIssuedCertificateRequest) (*lcmV1.UpdateIssuedCertificateResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Look up the certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Verify tenant access
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Check that at least one field is being updated
	if req.AutoRenewEnabled == nil && req.AutoRenewDaysBeforeExpiry == nil {
		return nil, lcmV1.ErrorBadRequest("at least one field must be provided for update")
	}

	// Perform the update
	updated, err := s.issuedCertRepo.UpdateAutoRenewSettings(ctx, req.GetId(), req.AutoRenewEnabled, req.AutoRenewDaysBeforeExpiry)
	if err != nil {
		return nil, err
	}

	s.log.Infof("Updated issued certificate %s auto-renew settings (enabled=%v, days=%v)",
		req.GetId(), req.AutoRenewEnabled, req.AutoRenewDaysBeforeExpiry)

	return &lcmV1.UpdateIssuedCertificateResponse{
		Certificate: mapIssuedCertToProto(updated),
	}, nil
}

// DeployCertificate deploys a certificate via the deployer module
func (s *IssuedCertificateService) DeployCertificate(ctx context.Context, req *lcmV1.DeployCertificateRequest) (*lcmV1.DeployCertificateResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	// Look up the certificate
	cert, err := s.issuedCertRepo.GetByID(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Verify tenant access
	if tenantID != 0 && cert.TenantID != tenantID {
		return nil, lcmV1.ErrorNotFound("issued certificate '%s' not found", req.GetId())
	}

	// Only allow deployment for issued certificates
	if cert.Status != issuedcertificate.StatusIssued {
		return nil, lcmV1.ErrorBadRequest("certificate must be in ISSUED status to deploy")
	}

	if s.deployerClient == nil {
		return nil, lcmV1.ErrorInternalServerError("deployer module is not available")
	}

	// Must provide either target or configuration
	if req.DeploymentTargetId == nil && req.TargetConfigurationId == nil {
		return nil, lcmV1.ErrorBadRequest("either deployment_target_id or target_configuration_id must be provided")
	}

	// Use platform context for cross-module call
	deployCtx := lcmClient.DetachedMetadataContext(ctx, tenantID)

	if req.DeploymentTargetId != nil {
		resp, err := s.deployerClient.DeployToTarget(deployCtx, *req.DeploymentTargetId, req.GetId())
		if err != nil {
			s.log.Errorf("Failed to deploy certificate %s to target %s: %v", req.GetId(), *req.DeploymentTargetId, err)
			return nil, lcmV1.ErrorInternalServerError("deployment failed: %v", err)
		}
		s.log.Infof("Deployed certificate %s to target %s, job=%s", req.GetId(), *req.DeploymentTargetId, resp.GetJob().GetId())
		return &lcmV1.DeployCertificateResponse{
			JobId:   resp.GetJob().GetId(),
			Message: "Deployment job created successfully",
		}, nil
	}

	resp, err := s.deployerClient.Deploy(deployCtx, *req.TargetConfigurationId, req.GetId())
	if err != nil {
		s.log.Errorf("Failed to deploy certificate %s to config %s: %v", req.GetId(), *req.TargetConfigurationId, err)
		return nil, lcmV1.ErrorInternalServerError("deployment failed: %v", err)
	}
	s.log.Infof("Deployed certificate %s to config %s, job=%s", req.GetId(), *req.TargetConfigurationId, resp.GetJob().GetId())
	return &lcmV1.DeployCertificateResponse{
		JobId:   resp.GetJob().GetId(),
		Message: "Deployment job created successfully",
	}, nil
}

// ListDeploymentTargets lists available deployment targets from the deployer module
func (s *IssuedCertificateService) ListDeploymentTargets(ctx context.Context, _ *lcmV1.ListDeploymentTargetsRequest) (*lcmV1.ListDeploymentTargetsResponse, error) {
	tenantID, _, err := s.getClientInfo(ctx)
	if err != nil {
		return nil, err
	}

	if s.deployerClient == nil {
		return &lcmV1.ListDeploymentTargetsResponse{
			Targets: []*lcmV1.DeploymentTargetInfo{},
		}, nil
	}

	deployCtx := lcmClient.DetachedMetadataContext(ctx, tenantID)
	resp, err := s.deployerClient.ListTargets(deployCtx)
	if err != nil {
		s.log.Warnf("Failed to list deployment targets: %v", err)
		return &lcmV1.ListDeploymentTargetsResponse{
			Targets: []*lcmV1.DeploymentTargetInfo{},
		}, nil
	}

	targets := make([]*lcmV1.DeploymentTargetInfo, 0, len(resp.GetItems()))
	for _, t := range resp.GetItems() {
		targets = append(targets, &lcmV1.DeploymentTargetInfo{
			Id:                 t.GetId(),
			Name:               t.GetName(),
			Description:        t.GetDescription(),
			ConfigurationCount: t.GetConfigurationCount(),
		})
	}

	return &lcmV1.ListDeploymentTargetsResponse{Targets: targets}, nil
}

// mapIssuedCertToProto maps a database entity to a proto message.
// When a certificate PEM is present we derive keyType/keySize from its SPKI
// instead of trusting the stored columns — historical records persisted the
// caller's requested values, which can diverge from what the issuer actually
// produced.
func mapIssuedCertToProto(cert *ent.IssuedCertificate) *lcmV1.IssuedCertificateInfo {
	keyType := string(cert.KeyType)
	keySize := cert.KeySize
	var lastIssuedAt *timestamppb.Timestamp
	if cert.CertPem != "" {
		if parsed, err := parseCertificatePEM(cert.CertPem); err == nil {
			if kt, ks := extractSPKIInfo(parsed); kt != "" {
				keyType = kt
				keySize = ks
			}
			// NotBefore is the truth source for "when this cert was
			// issued" — it advances on every successful renewal even
			// though created_at stays frozen at row-creation time.
			if !parsed.NotBefore.IsZero() {
				lastIssuedAt = timestamppb.New(parsed.NotBefore)
			}
		}
	}

	info := &lcmV1.IssuedCertificateInfo{
		Id:                        cert.ID,
		CommonName:                cert.CommonName,
		Domains:                   cert.Domains,
		IssuerName:                cert.IssuerName,
		IssuerType:                cert.IssuerType,
		Status:                    mapIssuedCertDBStatusToProto(cert.Status),
		AutoRenewEnabled:          cert.AutoRenewEnabled,
		AutoRenewDaysBeforeExpiry: cert.AutoRenewDaysBeforeExpiry,
		KeyType:                   keyType,
		KeySize:                   keySize,
		CreatedAt:                 timestamppb.New(cert.CreatedAt),
		UpdatedAt:                 timestamppb.New(cert.UpdatedAt),
		LastIssuedAt:              lastIssuedAt,
	}

	if !cert.ExpiresAt.IsZero() {
		info.ExpiresAt = timestamppb.New(cert.ExpiresAt)
	}

	if !cert.LastRenewalAt.IsZero() {
		info.LastRenewalAt = timestamppb.New(cert.LastRenewalAt)
	}

	if cert.ErrorMessage != "" {
		info.ErrorMessage = &cert.ErrorMessage
	}

	return info
}

// mapIssuedCertDBStatusToProto maps a database status to a proto status
func mapIssuedCertDBStatusToProto(status issuedcertificate.Status) lcmV1.IssuedCertificateStatus {
	switch status {
	case issuedcertificate.StatusPending:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_PENDING
	case issuedcertificate.StatusProcessing:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_PROCESSING
	case issuedcertificate.StatusIssued:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_ISSUED
	case issuedcertificate.StatusExpired:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_EXPIRED
	case issuedcertificate.StatusRevoked:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_REVOKED
	case issuedcertificate.StatusFailed:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_FAILED
	case issuedcertificate.StatusRenewed:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_RENEWED
	default:
		return lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_UNSPECIFIED
	}
}

// mapIssuedCertProtoStatusToDB maps a proto status to a database status
func mapIssuedCertProtoStatusToDB(status lcmV1.IssuedCertificateStatus) issuedcertificate.Status {
	switch status {
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_PENDING:
		return issuedcertificate.StatusPending
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_PROCESSING:
		return issuedcertificate.StatusProcessing
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_ISSUED:
		return issuedcertificate.StatusIssued
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_EXPIRED:
		return issuedcertificate.StatusExpired
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_REVOKED:
		return issuedcertificate.StatusRevoked
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_FAILED:
		return issuedcertificate.StatusFailed
	case lcmV1.IssuedCertificateStatus_ISSUED_CERTIFICATE_STATUS_RENEWED:
		return issuedcertificate.StatusRenewed
	default:
		return issuedcertificate.StatusUnspecified
	}
}
