package app

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/deploy"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/grpcapi"
	"github.com/go-freya/freya/services/lcm/internal/httpapi"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/renew"
	"github.com/go-freya/freya/services/lcm/internal/revoke"
	"github.com/go-freya/freya/services/lcm/internal/secrets"
	"github.com/go-freya/freya/services/lcm/internal/stats"
	"github.com/go-freya/freya/services/lcm/internal/stream"
	"github.com/go-freya/freya/services/lcm/internal/transfer"
	"github.com/go-freya/freya/services/lcm/internal/webhook"
)

// Version is reported by the health route.
const Version = "1.0.0"

// MeshTenantID keys lcm's own single mesh CA — the one trust root every
// platform workload's SVID chains to. It is bookkeeping for the CA table, not
// an auth tenant (the nil-ish sentinel UUID keeps it stable across restarts).
const MeshTenantID = "00000000-0000-0000-0000-000000000001"

// selfIssueTTL / selfIssueRenewBefore govern lcm's own self-issued SVID.
const (
	selfIssueTTL         = time.Hour
	selfIssueRenewBefore = 20 * time.Minute
)

// Wire builds the domain services, mounts every story's handlers on the HTTP
// server and the lcm.v1 gRPC services, and checks that every declared route has
// a handler so the contract and the implementation cannot drift.
func Wire(a *App) error {
	cfg := a.Cfg
	a.Authz = authz.New(a.Repo)
	if a.CA == nil {
		a.CA = ca.New(a.Repo, a.Envelope)
	}
	a.Issue = issue.New(a.Repo, a.CA, a.Envelope, a.Authz, a.Audit, nil)
	if cfg.DNS.Service != "" {
		// The "freya-dns" ACME provider publishes challenges through the DNS module.
		a.Issue.SetFreyaDNS(&lazyDNS{app: a, service: cfg.DNS.Service})
	}

	a.Hub = stream.NewHub(a.KV, stream.Config{ReplayWindow: cfg.ReplayWindow(), StreamsPerUser: cfg.Limits.StreamsPerUser, StreamsPerTenant: cfg.Limits.StreamsPerTenant}, a.Log)
	a.closers = append(a.closers, a.Hub.Close)

	a.Secrets = secrets.New(a.Repo, a.Envelope, a.Audit, nil)
	a.Webhook = webhook.New(a.Repo, a.Envelope, a.Audit, nil)
	a.Stats = stats.New(a.Repo, a.Hub, 24*time.Hour, nil)
	a.Revoke = revoke.New(a.Repo, a.CA, nil)
	a.Transfer = transfer.New(a.Repo, a.Envelope, a.Audit, nil)
	pub := hubPublisher{hub: a.Hub, wh: a.Webhook}

	tv := a.EnrollTokens
	if tv == nil {
		tv = stubEnrollTokens{}
	}
	a.Enroll = enroll.New(a.Repo, a.Issue, a.Authz, a.Audit, tv, enroll.Config{AutoApprove: true}, nil)
	a.Deploy = deploy.New(a.Repo, a.Authz, a.Envelope, a.Audit, nil)

	// HTTP handlers (every declared route is mounted).
	cd := httpapi.CertDeps{Issue: a.Issue, Perms: a.Perms, Pub: pub.Publish, PubFail: pub.PublishFailed}
	a.HTTP.RegisterIssuers(cd)
	a.HTTP.RegisterCertificates(cd)
	a.HTTP.RegisterGrants(httpapi.GrantDeps{Authz: a.Authz})
	a.HTTP.RegisterEnroll(httpapi.EnrollDeps{Enroll: a.Enroll, Perms: a.Perms})
	a.HTTP.RegisterDeploy(httpapi.DeployDeps{Deploy: a.Deploy})
	a.HTTP.RegisterStream(httpapi.StreamDeps{Hub: a.Hub, Audit: a.Audit})
	a.HTTP.RegisterSecrets(httpapi.SecretDeps{Secrets: a.Secrets})
	a.HTTP.RegisterWebhooks(httpapi.WebhookDeps{Webhooks: a.Webhook})
	a.HTTP.RegisterBackup(httpapi.BackupDeps{Transfer: a.Transfer, MaxBytes: cfg.Limits.BackupMaxBytes})
	a.HTTP.RegisterOps(httpapi.OpsDeps{Stats: a.Stats, Revoke: a.Revoke, Audit: a.Repo, Version: Version,
		Health: func(ctx context.Context) any { return a.Health(ctx) }, MeshTenantID: MeshTenantID})

	// gRPC servers (service-to-service + workload agents).
	grpcapi.Register(a.Freya.GRPC(), grpcapi.Deps{Issue: a.Issue, Enroll: a.Enroll, CA: a.CA, Repo: a.Repo, Hub: a.Hub})

	// Background workers: the async issuance job scheduler and the distributed
	// renewal scheduler.
	a.JobSched = enroll.NewScheduler(a.Enroll, enroll.SchedulerConfig{Interval: cfg.RenewalInterval(), Lease: cfg.LeaseDuration(), Batch: 50}, a.Log, a.Tick)
	a.RenewSched = renew.NewScheduler(a.Repo, sysRenewer{svc: a.Issue}, pub, renew.Config{Interval: cfg.RenewalInterval(), Workers: cfg.Renewal.Workers, ShortLivedFraction: cfg.Renewal.ShortLivedFraction, LongLivedWindow: cfg.LongLivedWindow()}, a.Log, nil, a.Tick)
	a.workers = append(a.workers, func(ctx context.Context) { a.JobSched.Run(ctx) })
	a.workers = append(a.workers, func(ctx context.Context) { a.RenewSched.Run(ctx) })

	if cfg.EnrollListener != "" {
		if err := a.startEnrollListener(cfg.EnrollListener); err != nil {
			return err
		}
	}
	return a.CheckRoutes()
}
