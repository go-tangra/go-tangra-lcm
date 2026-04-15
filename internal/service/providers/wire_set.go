//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// This file defines the dependency injection ProviderSet for the data layer and contains no business logic.
// The build tag `wireinject` excludes this source from normal `go build` and final binaries.
// Run `go generate ./...` or `go run github.com/google/wire/cmd/wire` to regenerate the Wire output (e.g. `wire_gen.go`), which will be included in final builds.
// Keep provider constructors here only; avoid init-time side effects or runtime logic in this file.

package providers

import (
	"github.com/go-tangra/go-tangra-lcm/internal/client"
	"github.com/go-tangra/go-tangra-lcm/internal/event"
	"github.com/go-tangra/go-tangra-lcm/internal/metrics"
	"github.com/go-tangra/go-tangra-lcm/internal/service"
	"github.com/go-tangra/go-tangra-lcm/internal/webhook"

	"github.com/google/wire"
)

// ProviderSet is the Wire provider set for service layer.
var ProviderSet = wire.NewSet(
	metrics.NewCollector,
	service.NewSystemService,
	service.NewLcmClientService,
	service.NewIssuerService,
	service.NewCertificateJobService,
	service.NewIssuedCertificateService,
	service.NewTenantSecretService,
	service.NewAuditLogService,
	service.NewMtlsCertService,
	service.NewCertificatePermissionService,
	service.NewMtlsCertificateRequestService,
	service.NewStatisticsService,
	service.NewBackupService,
	service.NewBootstrapService,
	ProvideRenewalConfig,
	ProvideLCMConfig,
	service.NewRenewalScheduler,
	event.NewPublisher,
	ProvidePrivateKeyEncryptor,
	webhook.NewService,
	client.NewRegistrationClient,
	client.NewModuleDialer,
	client.NewNotificationClient,
	client.NewDeployerClient,
)
