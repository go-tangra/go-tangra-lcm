package server

import (
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/cert"
	"github.com/go-tangra/go-tangra-lcm/internal/service"
)

// bootstrapDefaultAddr is the listen address used when
// LCM_BOOTSTRAP_ADDR is not set. Port 9101 is deliberately distinct
// from the mTLS gRPC (:9100) — modules dial this port BEFORE they
// have a client cert, so the listener cannot require one.
const bootstrapDefaultAddr = "0.0.0.0:9101"

// BootstrapGRPCServer is a typed wrapper around *grpc.Server used
// only so Wire can distinguish the bootstrap listener from the main
// mTLS listener (both are *grpc.Server otherwise — Wire would refuse
// to inject because the two providers return the same type).
type BootstrapGRPCServer struct {
	*grpc.Server
}

// NewBootstrapGRPCServer is the second gRPC server lcm-service
// runs: a plain-TLS surface (no client-cert verification) that hosts
// only LcmBootstrapService. Modules dial it at startup to pin the CA
// fingerprint and have their CSRs signed.
//
// Auth comes from the shared MODULE_BOOTSTRAP_SECRET inside each RPC
// body — checked by SignCertificateService server-side. Network-layer
// auth (mTLS) cannot be required here because the whole point is to
// bootstrap modules that do not yet have a client cert.
//
// The middleware stack is intentionally minimal: recovery + logging
// only. No audit-log writes (the SignModuleCertificate handler logs
// successful issuances itself) and no MTLS middleware (no client
// cert to inspect).
func NewBootstrapGRPCServer(
	ctx *bootstrap.Context,
	certManager *cert.CertManager,
	signSvc *service.SignCertificateService,
) *BootstrapGRPCServer {
	logger := ctx.GetLogger()
	l := log.NewHelper(log.With(logger, "module", "server/bootstrap-grpc"))

	tlsConfig, err := certManager.GetServerTLSConfigNoClientAuth()
	if err != nil {
		l.Fatalf("Failed to build bootstrap TLS config: %v", err)
	}

	// The bootstrap port is read from LCM_BOOTSTRAP_ADDR rather than
	// the kratos-bootstrap Server proto so the rework can ship without
	// touching the upstream conf schema. Default :9101 is fine for
	// every environment we run.
	addr := os.Getenv("LCM_BOOTSTRAP_ADDR")
	if addr == "" {
		addr = bootstrapDefaultAddr
	}

	opts := []grpc.ServerOption{
		grpc.Address(addr),
		grpc.TLSConfig(tlsConfig),
		grpc.Middleware(
			recovery.Recovery(),
			loggingFilter(logger),
		),
	}

	srv := grpc.NewServer(opts...)
	commonV1.RegisterLcmBootstrapServiceServer(srv, signSvc)

	l.Infof("bootstrap gRPC server configured (TLS, no client-cert auth) on %s", addr)
	return &BootstrapGRPCServer{Server: srv}
}

// loggingFilter wraps kratos's logging middleware so we can drop
// fields here if we ever need to scrub the secret from logs. The
// secret never reaches log output today (the redacted proto wrapper
// would handle it if we registered the redacted server), but keeping
// the indirection makes it cheap to add scrubbing later.
func loggingFilter(logger log.Logger) middleware.Middleware {
	return logging.Server(logger)
}
