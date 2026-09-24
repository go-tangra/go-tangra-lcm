// Package app wires the lcm service: configuration -> Freya runtime ->
// TimescaleDB, Valkey, KEK envelope, audit -> token verifier -> browser API on
// the Freya HTTP server (reached only through the gateway) and the lcm.v1 gRPC
// API -> gateway registration. cmd/lcmsvc and the integration harness use it.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	kmiddleware "github.com/go-kratos/kratos/v3/middleware"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/config"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/renew"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/revoke"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/selfidentity"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stats"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream/valkeykv"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/transfer"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
	"github.com/go-tangra/go-tangra-lcm/v4/pkg/lcmmanifest"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
	"github.com/go-tangra/go-tangra/v4"
)

// Options override infrastructure (tests) and attach optional parts.
type Options struct {
	Logger       slog.Handler
	KV           stream.Client
	KEK          []byte
	Verifier     httpapi.Verifier
	GRPCAuth     kmiddleware.Middleware
	Remote       fs.FS
	Perms        httpapi.PermissionChecker
	EnrollTokens enroll.TokenVerifier
	Freya        []freya.Option
	Migrate      bool
	// Register lets the caller mount handlers after the core is wired (Wire).
	Register func(a *App) error
}

// App holds every wired component. User-story phases add their services.
type App struct {
	Cfg          config.Config
	Log          *slog.Logger
	Freya        *freya.App
	Store        *store.Store
	Repo         repo.Store
	KV           stream.Client
	Envelope     *sealed.Envelope
	Audit        *audit.Writer
	Verifier     httpapi.Verifier
	GRPCAuth     kmiddleware.Middleware
	HTTP         *httpapi.Server
	Authz        *authz.Authorizer
	CA           *ca.Authority
	selfIdentity *selfidentity.Provider
	Issue        *issue.Service
	Enroll       *enroll.Service
	EnrollTokens enroll.TokenVerifier
	Deploy       *deploy.Service
	Hub          *stream.Hub
	JobSched     *enroll.Scheduler
	RenewSched   *renew.Scheduler
	Secrets      *secrets.Service
	Webhook      *webhook.Service
	Stats        *stats.Service
	Revoke       *revoke.Service
	Transfer     *transfer.Service
	Perms        httpapi.PermissionChecker
	lastTick     atomic.Int64
	closers      []func()
	workers      []func(ctx context.Context)
}

// Build validates cfg and connects every dependency; nothing is served yet.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}
	built := &App{Cfg: cfg, Log: log}
	a = built
	defer func() {
		if err != nil {
			built.Close()
		}
	}()
	if o.Migrate {
		dsn := cfg.DB.MigrateDSN
		if dsn == "" {
			dsn = cfg.DB.DSN
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return nil, err
		}
	}
	if a.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Store.Close)
	a.Repo = repodb.New(a.Store)
	a.KV = o.KV
	if a.KV == nil {
		vc := valkeykv.Config{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			if vc.CAPEM, err = os.ReadFile(cfg.Valkey.CAFile); err != nil {
				return nil, fmt.Errorf("valkey ca: %w", err)
			}
		}
		if a.KV, err = valkeykv.New(vc); err != nil {
			return nil, err
		}
	}
	a.closers = append(a.closers, a.KV.Close)
	kek := o.KEK
	if kek == nil {
		if kek, err = sealed.LoadKEK(cfg.KEK.Source, cfg.KEK.Path, cfg.KEK.Env); err != nil {
			return nil, err
		}
	}
	if a.Envelope, err = sealed.NewEnvelope(kek); err != nil {
		return nil, err
	}
	a.Audit = audit.NewWriter(a.Repo, func(err error) { log.Error("audit write failed", "err", err) })
	a.closers = append(a.closers, a.Audit.Close)

	// lcm is the platform CA, so it bootstraps its OWN SVID directly from its
	// DB-sealed root (no external cert file) and every workload chains to that
	// same one root. The CA is built here, before freya.New, and injected as the
	// identity provider; Wire reuses a.CA. The private key is generated in
	// memory and never persisted.
	a.CA = ca.New(a.Repo, a.Envelope)
	selfProv, serr := selfidentity.New(ctx, selfidentity.Config{
		CA: a.CA, TenantID: MeshTenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
		TTL: selfIssueTTL, RenewBefore: selfIssueRenewBefore,
	})
	if serr != nil {
		return nil, fmt.Errorf("self-issue identity: %w", serr)
	}
	a.selfIdentity = selfProv
	a.closers = append(a.closers, func() { _ = selfProv.Close() })

	fopts := append([]freya.Option{freya.WithLogger(handler), freya.WithIdentityProvider(selfProv)}, o.Freya...)
	if a.Freya, err = freya.New(cfg.Config, fopts...); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Freya.Close)
	a.Verifier, a.GRPCAuth, a.Perms, a.EnrollTokens = o.Verifier, o.GRPCAuth, o.Perms, o.EnrollTokens
	if a.Verifier == nil || a.Perms == nil || a.EnrollTokens == nil {
		conn, err := a.Freya.Client(ctx, "auth")
		if err != nil {
			return nil, fmt.Errorf("auth client: %w", err)
		}
		if a.Verifier == nil {
			a.Verifier = authclient.New(authclient.Config{Issuer: cfg.Gateway.Issuer}, authclient.GRPCKeys{Client: authv1.NewKeysClient(conn)}, authclient.GRPCRevocations{Client: authv1.NewSessionsClient(conn)})
		}
		if a.Perms == nil {
			a.Perms = AuthPerms{Client: authv1.NewAuthorizationClient(conn)}
		}
		if a.EnrollTokens == nil {
			a.EnrollTokens = authEnrollTokens{client: authv1.NewEnrollmentClient(conn)}
		}
	}
	hopts := []httpapi.Option{httpapi.WithVerifier(a.Verifier)}
	if o.Remote != nil {
		hopts = append(hopts, httpapi.WithRemote(o.Remote))
	}
	if a.HTTP, err = httpapi.NewHandler(a.Freya, hopts...); err != nil {
		return nil, err
	}
	a.Freya.HTTP().HandlePrefix("/", a.HTTP.Handler())
	if o.Register != nil {
		if err := o.Register(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// CheckRoutes fails when a declared route has no handler.
func (a *App) CheckRoutes() error {
	if missing := a.HTTP.Missing(); len(missing) > 0 {
		return fmt.Errorf("app: %d routes declared in the OpenAPI document without a handler (first: %s)", len(missing), missing[0])
	}
	return nil
}

// Health reports the dependencies for the health route and bootstrap.
type Health struct {
	DB                string    `json:"database"`
	Valkey            string    `json:"valkey"`
	SchedulerLastTick time.Time `json:"scheduler_last_tick"`
}

// Health checks the database and Valkey, each within its own deadline.
func (a *App) Health(ctx context.Context) Health {
	h := Health{DB: "ok", Valkey: "ok"}
	dbCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := a.Store.Ping(dbCtx); err != nil {
		h.DB = "unreachable"
	}
	cancel()
	kvCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := a.KV.Ping(kvCtx); err != nil {
		h.Valkey = "unreachable"
	}
	cancel()
	if t := a.lastTick.Load(); t > 0 {
		h.SchedulerLastTick = time.Unix(0, t)
	}
	return h
}

// Tick records a scheduler pass (health).
func (a *App) Tick() { a.lastTick.Store(time.Now().UnixNano()) }

// AddWorker registers a background worker started by Run (used by story phases).
func (a *App) AddWorker(w func(ctx context.Context)) { a.workers = append(a.workers, w) }

// AddCloser registers a cleanup function (used by story phases).
func (a *App) AddCloser(c func()) { a.closers = append(a.closers, c) }

// Run serves until ctx is done: the verifier feed, the gateway lease and
// background workers stop with it.
func (a *App) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if v, ok := a.Verifier.(*authclient.Verifier); ok {
		go func() {
			for wctx.Err() == nil {
				if err := v.Start(wctx, func(err error) { a.Log.Warn("verifier", "err", err) }); err == nil {
					return
				}
				a.Log.Warn("verifier start failed; retrying")
				select {
				case <-wctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	go a.register(wctx)
	for _, w := range a.workers {
		go w(wctx)
	}
	go func() {
		for wctx.Err() == nil && !a.Freya.Ready() {
			time.Sleep(100 * time.Millisecond)
		}
		a.seedLoop(wctx)
	}()
	return a.Freya.Run(ctx)
}

// register keeps the gateway lease for the manifest.
func (a *App) register(ctx context.Context) {
	for ctx.Err() == nil && !a.Freya.Ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	man, err := lcmmanifest.Manifest()
	if err != nil {
		a.Log.Error("gateway manifest", "err", err)
		return
	}
	httpEP, err := a.Freya.HTTP().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: http endpoint", "err", err)
		return
	}
	grpcEP, err := a.Freya.GRPC().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: grpc endpoint", "err", err)
		return
	}
	var client *gatewayclient.Client
	for ctx.Err() == nil && client == nil {
		conn, err := a.Freya.Client(ctx, a.Cfg.Gateway.Service)
		if err != nil {
			a.Log.Warn("gateway connection", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		client, err = gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: a.Log,
			OnState: func(s gatewayclient.State) {
				a.Log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
			}})
		if err != nil {
			a.Log.Error("gateway client", "err", err)
			return
		}
	}
	if client != nil {
		if err := client.Run(ctx); err != nil {
			a.Log.Error("gateway registration", "err", err)
		}
	}
}

// Close releases everything Build acquired (idempotent, reverse order).
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}
