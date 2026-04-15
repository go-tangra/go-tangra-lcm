package client

import (
	"context"
	"fmt"
	"os"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
	grpcMD "google.golang.org/grpc/metadata"

	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-common/registration"
)

// NewRegistrationClient creates a registration client connected to admin-service.
// This is created early (during Wire DI) so its admin connection can be shared
// with ModuleDialer for module-to-module resolution.
func NewRegistrationClient(ctx *bootstrap.Context) (*registration.Client, error) {
	adminEndpoint := os.Getenv("ADMIN_GRPC_ENDPOINT")
	if adminEndpoint == "" {
		return nil, nil
	}

	cfg := &registration.Config{
		AdminEndpoint: adminEndpoint,
		MaxRetries:    60,
	}

	return registration.NewClient(ctx.GetLogger(), cfg)
}

// NewModuleDialer creates a ModuleDialer from the registration client's admin connection.
// Respects CERTS_DIR env var for dev mode (default: /app/certs).
func NewModuleDialer(ctx *bootstrap.Context, regClient *registration.Client) *grpcx.ModuleDialer {
	if regClient == nil {
		return nil
	}
	certsDir := os.Getenv("CERTS_DIR")
	return grpcx.NewModuleDialer(ctx.GetLogger(), "lcm", regClient.AdminConn(), certsDir)
}

// DetachedMetadataContext extracts gRPC metadata from the incoming request context
// and builds a new outgoing context based on context.Background().
// Use this for async goroutines where the request context will be canceled.
func DetachedMetadataContext(ctx context.Context, tenantID uint32) context.Context {
	outMD := grpcMD.New(map[string]string{
		"x-md-global-tenant-id": fmt.Sprintf("%d", tenantID),
	})

	if inMD, ok := grpcMD.FromIncomingContext(ctx); ok {
		for _, key := range []string{"x-md-global-user-id", "x-md-global-username", "x-md-global-roles"} {
			if vals := inMD.Get(key); len(vals) > 0 {
				outMD.Set(key, vals[0])
			}
		}
	}

	return grpcMD.NewOutgoingContext(context.Background(), outMD)
}
