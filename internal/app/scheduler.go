package app

import (
	"context"
	"sync"

	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/taskexec"
	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
	schedulerv1 "github.com/go-tangra/go-tangra-scheduler/sdk/v4/api/proto/scheduler/v1"
	"github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/schedulerclient"
	sdktask "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"
	"github.com/go-tangra/go-tangra/v4/authn"
)

// wireScheduler serves scheduler.v1.TaskExecutor (always: the mesh policy
// admits only svc/scheduler and the SDK server re-checks the peer) and, when
// task_scheduler.enabled, keeps lcm's task types registered with the
// scheduler (feature 026).
func (a *App) wireScheduler() {
	cfg := a.Cfg
	exec := &taskexec.Expiring{Repo: a.Repo, Notify: &lazyNotify{app: a, service: cfg.Notification.Service}, Log: a.Log}
	scheduler := cfg.TaskScheduler.Service
	if scheduler == "" {
		scheduler = sdktask.DefaultScheduler
	}
	schedulerv1.RegisterTaskExecutorServer(a.Freya.GRPC(), sdktask.NewServer(taskexec.Handlers(exec), sdktask.Options{
		Caller: schedulerCaller(cfg.TrustDomain), Scheduler: scheduler, Log: a.Log,
	}))
	if !cfg.TaskScheduler.Enabled {
		return
	}
	reg := &schedulerclient.Registrar{
		Dial: func(ctx context.Context) (grpc.ClientConnInterface, error) {
			return a.Freya.Client(ctx, cfg.TaskScheduler.Service)
		},
		Types: taskexec.Descriptors(),
		Log:   a.Log,
	}
	a.workers = append(a.workers, reg.Run)
}

// schedulerCaller returns the verified peer's service name, only for a peer
// of lcm's own trust domain.
func schedulerCaller(trustDomain string) func(ctx context.Context) (string, bool) {
	return func(ctx context.Context) (string, bool) {
		p, ok := authn.FromContext(ctx)
		if !ok || p.ID.TrustDomain() != trustDomain {
			return "", false
		}
		return p.ID.ServiceName(), true
	}
}

// lazyNotify is the notification module client behind the scheduled digest,
// dialled over SPIFFE mTLS on first use so lcm starts while notification is
// down. A dial failure is reported as retryable.
type lazyNotify struct {
	app     *App
	service string
	mu      sync.Mutex
	c       *notifyclient.Client
}

func (l *lazyNotify) client(ctx context.Context) (*notifyclient.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c == nil {
		conn, err := l.app.Freya.Client(ctx, l.service)
		if err != nil {
			return nil, err
		}
		l.c = notifyclient.New(conn)
	}
	return l.c, nil
}

// SendKey sends one keyed notification through the notification module.
func (l *lazyNotify) SendKey(ctx context.Context, tenantID, key, recipient string, vars map[string]string, correlationID string) (notifyclient.Result, error) {
	c, err := l.client(ctx)
	if err != nil {
		l.app.Log.WarnContext(ctx, "notification client", "err", err)
		return notifyclient.Result{Retryable: true, Reason: "notification unreachable"}, nil
	}
	return c.SendKey(ctx, tenantID, key, recipient, vars, correlationID)
}
