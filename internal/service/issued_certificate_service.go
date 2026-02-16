package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
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
}

// NewIssuedCertificateService creates a new IssuedCertificateService
func NewIssuedCertificateService(
	ctx *bootstrap.Context,
	issuedCertRepo *data.IssuedCertificateRepo,
	clientRepo *data.LcmClientRepo,
	mtlsCertRepo *data.MtlsCertificateRepo,
	renewalRepo *data.CertificateRenewalRepo,
) *IssuedCertificateService {
	return &IssuedCertificateService{
		log:            ctx.NewLoggerHelper("lcm/service/issued-certificate"),
		issuedCertRepo: issuedCertRepo,
		clientRepo:     clientRepo,
		mtlsCertRepo:   mtlsCertRepo,
		renewalRepo:    renewalRepo,
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

// mapIssuedCertToProto maps a database entity to a proto message
func mapIssuedCertToProto(cert *ent.IssuedCertificate) *lcmV1.IssuedCertificateInfo {
	info := &lcmV1.IssuedCertificateInfo{
		Id:                       cert.ID,
		CommonName:               cert.CommonName,
		Domains:                  cert.Domains,
		IssuerName:               cert.IssuerName,
		IssuerType:               cert.IssuerType,
		Status:                   mapIssuedCertDBStatusToProto(cert.Status),
		AutoRenewEnabled:         cert.AutoRenewEnabled,
		AutoRenewDaysBeforeExpiry: cert.AutoRenewDaysBeforeExpiry,
		KeyType:                  string(cert.KeyType),
		KeySize:                  cert.KeySize,
		CreatedAt:                timestamppb.New(cert.CreatedAt),
		UpdatedAt:                timestamppb.New(cert.UpdatedAt),
	}

	if !cert.ExpiresAt.IsZero() {
		info.ExpiresAt = timestamppb.New(cert.ExpiresAt)
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
