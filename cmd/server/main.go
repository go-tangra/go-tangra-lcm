package main

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/transport/grpc"

	conf "github.com/tx7do/kratos-bootstrap/api/gen/go/conf/v1"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/registration"
	"github.com/go-tangra/go-tangra-common/service"
	"github.com/go-tangra/go-tangra-lcm/cmd/server/assets"
	lcmBootstrap "github.com/go-tangra/go-tangra-lcm/internal/bootstrap"
	lcmCnf "github.com/go-tangra/go-tangra-lcm/internal/conf"
	lcmService "github.com/go-tangra/go-tangra-lcm/internal/service"
	lcmWebhook "github.com/go-tangra/go-tangra-lcm/internal/webhook"

	// Register DNS providers for ACME certificate issuance
	_ "github.com/go-tangra/go-tangra-lcm/pkg/dns/init"

	// Import ent/runtime to initialize schema hooks and policies
	_ "github.com/go-tangra/go-tangra-lcm/internal/data/ent/runtime"
)

var (
	// Module info
	moduleID    = "lcm"
	moduleName  = "LCM"
	version     = "1.0.0"
	description = "Certificate Lifecycle Management service for issuing, renewing, and managing TLS certificates"
)

// Global references for cleanup
var globalRenewalScheduler *lcmService.RenewalScheduler
var globalWebhookService *lcmWebhook.Service
var globalRegHelper *registration.RegistrationHelper

func newApp(
	ctx *bootstrap.Context,
	gs *grpc.Server,
	bootstrapSvc *lcmBootstrap.BootstrapService,
	renewalScheduler *lcmService.RenewalScheduler,
	webhookService *lcmWebhook.Service,
) *kratos.App {
	// Run mTLS certificate bootstrap before starting the app
	if err := bootstrapSvc.Bootstrap(context.Background()); err != nil {
		log.Fatalf("mTLS bootstrap failed: %v", err)
	}

	// Start the renewal scheduler and store reference for cleanup
	globalRenewalScheduler = renewalScheduler
	if renewalScheduler != nil {
		if err := renewalScheduler.Start(); err != nil {
			log.Warnf("Failed to start renewal scheduler: %v", err)
		}
	}

	// Start the webhook service and store reference for cleanup
	globalWebhookService = webhookService
	if webhookService != nil {
		if err := webhookService.Start(); err != nil {
			log.Warnf("Failed to start webhook service: %v", err)
		}
	}

	globalRegHelper = registration.StartRegistration(ctx, ctx.GetLogger(), &registration.Config{
		ModuleID:          moduleID,
		ModuleName:        moduleName,
		Version:           version,
		Description:       description,
		GRPCEndpoint:      registration.GetGRPCAdvertiseAddr(ctx, "0.0.0.0:9100"),
		AdminEndpoint:     registration.GetEnvOrDefault("ADMIN_GRPC_ENDPOINT", ""),
		OpenapiSpec:       assets.OpenApiData,
		ProtoDescriptor:   assets.DescriptorData,
		MenusYaml:         assets.MenusData,
		HeartbeatInterval: 30 * time.Second,
		RetryInterval:     5 * time.Second,
		MaxRetries:        60,
	})

	return bootstrap.NewApp(ctx, gs)
}

// stopServices stops background services (called from wire cleanup)
func stopServices() {
	if globalRenewalScheduler != nil {
		if err := globalRenewalScheduler.Stop(); err != nil {
			log.Warnf("Failed to stop renewal scheduler: %v", err)
		}
	}
	if globalWebhookService != nil {
		if err := globalWebhookService.Stop(); err != nil {
			log.Warnf("Failed to stop webhook service: %v", err)
		}
	}
}

func runApp() error {
	ctx := bootstrap.NewContext(
		context.Background(),
		&conf.AppInfo{
			Project: service.Project,
			AppId:   service.AdminService,
			Version: version,
		},
	)
	ctx.RegisterCustomConfig("lcm", &lcmCnf.LCM{})
	ctx.RegisterCustomConfig("vault", &lcmCnf.Vault{})

	// Ensure services are stopped on exit
	defer stopServices()
	defer globalRegHelper.Stop()

	return bootstrap.RunApp(ctx, initApp)
}

func main() {
	if err := runApp(); err != nil {
		panic(err)
	}
}

