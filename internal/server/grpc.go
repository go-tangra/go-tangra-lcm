package server

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-lcm/internal/data"
	"github.com/go-tangra/go-tangra-lcm/internal/service"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/cert"
	lcmMiddleware "github.com/go-tangra/go-tangra-lcm/pkg/middleware"
	"github.com/go-tangra/go-tangra-lcm/pkg/middleware/audit"
	appViewer "github.com/go-tangra/go-tangra-common/viewer"
)

// NewWhiteListMatcher Creates grpc whitelist for public endpoints
func newGrpcWhiteListMatcher() selector.MatchFunc {
	whiteList := make(map[string]bool)
	// All LCM client service endpoints are public - clients authenticate with shared secrets
	whiteList["/lcm.service.v1.LcmClientService/RegisterLcmClient"] = true
	whiteList["/lcm.service.v1.LcmClientService/GetRequestStatus"] = true
	whiteList["/lcm.service.v1.LcmClientService/DownloadClientCertificate"] = true
	// System service endpoints are public
	whiteList["/lcm.service.v1.SystemService/HealthCheck"] = true
	// Bootstrap service is public - modules authenticate with module_registration_secret
	whiteList["/common.service.v1.LcmBootstrapService/BootstrapCertificates"] = true

	return func(ctx context.Context, operation string) bool {
		if _, ok := whiteList[operation]; ok {
			return false
		}
		return true
	}
}

// systemViewerMiddleware injects system viewer context for all requests
// This allows the LCM service to bypass tenant privacy checks at the ent level
func systemViewerMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = appViewer.NewSystemViewerContext(ctx)
			return handler(ctx, req)
		}
	}
}

// NewMiddleware Create gRPC Middleware
func newGrpcMiddleware(
	logger log.Logger,
	auditLogRepo *data.AuditLogRepo,
) []middleware.Middleware {
	var ms []middleware.Middleware

	ms = append(ms, recovery.Recovery())
	ms = append(ms, systemViewerMiddleware()) // Inject system viewer for ENT privacy
	// Add mTLS middleware for client certificate authentication FIRST
	// This must run before the operation logging to populate client context
	ms = append(ms, lcmMiddleware.MTLSMiddleware(logger))
	ms = append(ms, logging.Server(logger))

	// Add audit logging middleware with cryptographic signing
	// This captures operation details, signs them for integrity, and writes to database
	ms = append(ms, audit.Server(logger,
		audit.WithServiceName("lcm-service"),
		audit.WithWriteAuditLogFunc(audit.NewDatabaseWriter(auditLogRepo)),
		audit.WithSkipOperations(
			"/lcm.service.v1.SystemService/HealthCheck",
			"/lcm.service.v1.BackupService/ExportBackup",
			"/lcm.service.v1.BackupService/ImportBackup",
		),
	))

	return ms
}

// NewGRPCServer new a gRPC server.
func NewGRPCServer(
	ctx *bootstrap.Context,
	certManager *cert.CertManager,
	auditLogRepo *data.AuditLogRepo,
	systemSvc *service.SystemService,
	lcmClientSvc *service.LcmClientService,
	issuerSvc *service.IssuerService,
	certJobSvc *service.CertificateJobService,
	issuedCertSvc *service.IssuedCertificateService,
	tenantSecretSvc *service.TenantSecretService,
	auditLogSvc *service.AuditLogService,
	mtlsCertSvc *service.MtlsCertService,
	certPermissionSvc *service.CertificatePermissionService,
	mtlsCertRequestSvc *service.MtlsCertificateRequestService,
	statisticsSvc *service.StatisticsService,
	backupSvc *service.BackupService,
	bootstrapSvc *service.BootstrapService,
) *grpc.Server {
	cfg := ctx.GetConfig()
	logger := ctx.GetLogger()

	l := log.NewHelper(log.With(logger, "module", "server/grpc"))
	// Get TLS configuration from certificate manager
	tlsConfig, err := certManager.GetServerTLSConfig()
	if err != nil {
		l.Fatalf("Failed to get TLS config: %v", err)
	}
	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.TLSConfig(tlsConfig),
		grpc.Middleware(newGrpcMiddleware(logger, auditLogRepo)...),
	}

	// Add server configuration from bootstrap config
	if cfg.Server != nil && cfg.Server.Grpc != nil {
		if cfg.Server.Grpc.Addr != "" {
			opts = append(opts, grpc.Address(cfg.Server.Grpc.Addr))
		}
		if cfg.Server.Grpc.Timeout != nil {
			opts = append(opts, grpc.Timeout(cfg.Server.Grpc.Timeout.AsDuration()))
		}
	}

	// Create the gRPC server
	srv := grpc.NewServer(opts...)

	// Register services with redacted wrappers to prevent sensitive data from leaking in logs
	lcmV1.RegisterRedactedSystemServiceServer(srv, systemSvc, nil)
	lcmV1.RegisterRedactedLcmClientServiceServer(srv, lcmClientSvc, nil)
	lcmV1.RegisterRedactedLcmIssuerServiceServer(srv, issuerSvc, nil)
	lcmV1.RegisterRedactedLcmCertificateJobServiceServer(srv, certJobSvc, nil)
	lcmV1.RegisterRedactedLcmIssuedCertificateServiceServer(srv, issuedCertSvc, nil)
	lcmV1.RegisterRedactedTenantSecretServiceServer(srv, tenantSecretSvc, nil)
	lcmV1.RegisterRedactedAuditLogServiceServer(srv, auditLogSvc, nil)
	lcmV1.RegisterRedactedLcmMtlsCertificateServiceServer(srv, mtlsCertSvc, nil)
	lcmV1.RegisterRedactedCertificatePermissionServiceServer(srv, certPermissionSvc, nil)
	lcmV1.RegisterRedactedLcmMtlsCertificateRequestServiceServer(srv, mtlsCertRequestSvc, nil)
	lcmV1.RegisterRedactedLcmStatisticsServiceServer(srv, statisticsSvc, nil)
	lcmV1.RegisterRedactedBackupServiceServer(srv, backupSvc, nil)
	commonV1.RegisterLcmBootstrapServiceServer(srv, bootstrapSvc)
	l.Info("gRPC server configured with TLS and all LCM services")

	return srv
}
