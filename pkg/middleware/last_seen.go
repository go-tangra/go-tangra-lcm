package middleware

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/go-tangra/go-tangra-lcm/internal/data"
	"github.com/go-tangra/go-tangra-lcm/pkg/client"

	appViewer "github.com/go-tangra/go-tangra-common/viewer"
)

const lastSeenThrottle = 5 * time.Minute

// LastSeenMiddleware updates the last_seen_at timestamp for mTLS certificates.
// It runs after MTLSMiddleware and reads ClientInfo from context.
// Updates are throttled to at most once per 5 minutes per serial number
// and executed in a fire-and-forget goroutine to avoid blocking requests.
func LastSeenMiddleware(logger log.Logger, mtlsCertRepo *data.MtlsCertificateRepo) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/last_seen"))
	var lastSeen sync.Map // serial number string -> time.Time

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			if info, ok := client.GetClientInfoFromContext(ctx); ok && info.IsAuthenticated && info.SerialNumber != "" {
				serial := info.SerialNumber
				now := time.Now()

				if last, loaded := lastSeen.Load(serial); loaded {
					if now.Sub(last.(time.Time)) < lastSeenThrottle {
						return handler(ctx, req)
					}
				}

				lastSeen.Store(serial, now)

				serialInt, err := strconv.ParseInt(serial, 10, 64)
				if err != nil {
					l.Debugf("skipping last_seen update: non-numeric serial %s", serial)
					return handler(ctx, req)
				}

				go func() {
					bgCtx := appViewer.NewSystemViewerContext(context.Background())
					if err := mtlsCertRepo.UpdateLastSeen(bgCtx, serialInt); err != nil {
						l.Warnf("failed to update last_seen_at for serial %s: %v", serial, err)
					}
				}()
			}

			return handler(ctx, req)
		}
	}
}
