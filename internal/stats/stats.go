// Package stats reports per-tenant certificate-authority statistics for the
// dashboard: certificates by status, issuers, jobs, connected clients,
// certificates expiring soon, recent errors and the number of open live
// streams.
package stats

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// Repo reads the aggregate counts (repo.Store satisfies it).
type Repo interface {
	TenantStats(ctx context.Context, tenantID string, now time.Time, window time.Duration) (store.Stats, error)
}

// Hub reports the number of open live streams (the SSE Hub satisfies it).
type Hub interface {
	OpenStreams() int
}

// Service computes the statistics view.
type Service struct {
	repo   Repo
	hub    Hub
	window time.Duration
	now    func() time.Time
}

// New builds the service. window bounds "recent errors" and "operations";
// 24h is the usual value.
func New(repo Repo, hub Hub, window time.Duration, clock func() time.Time) *Service {
	if window <= 0 {
		window = 24 * time.Hour
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{repo: repo, hub: hub, window: window, now: clock}
}

// View is the statistics response.
type View struct {
	Issuers       int64            `json:"issuers"`
	Certificates  map[string]int64 `json:"certificates"`
	Jobs          map[string]int64 `json:"jobs"`
	Clients       int64            `json:"clients"`
	ExpiringSoon  int64            `json:"expiring_soon"`
	RecentErrors  int64            `json:"recent_errors"`
	Operations24h int64            `json:"operations_24h"`
	OpenStreams   int              `json:"open_streams"`
}

// Tenant returns the statistics for one tenant.
func (s *Service) Tenant(ctx context.Context, tenantID string) (View, error) {
	st, err := s.repo.TenantStats(ctx, tenantID, s.now(), s.window)
	if err != nil {
		return View{}, err
	}
	v := View{
		Issuers: st.Issuers, Certificates: st.Certificates, Jobs: st.Jobs, Clients: st.Clients,
		ExpiringSoon: st.ExpiringSoon, RecentErrors: st.RecentErrors, Operations24h: st.Operations24h,
	}
	if v.Certificates == nil {
		v.Certificates = map[string]int64{}
	}
	if v.Jobs == nil {
		v.Jobs = map[string]int64{}
	}
	if s.hub != nil {
		v.OpenStreams = s.hub.OpenStreams()
	}
	return v, nil
}
