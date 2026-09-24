package httpapi

import (
	"errors"
	"net/http"
	"os"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
)

// StreamDeps are the services behind the live certificate-event stream.
type StreamDeps struct {
	Hub   *stream.Hub
	Audit *audit.Writer
}

// RegisterStream mounts GET /stream (contracts/stream.md): a per-signed-in-user
// SSE stream of certificate-update events (issued|renewed|revoked).
func (s *Server) RegisterStream(d StreamDeps) {
	instance, _ := os.Hostname()
	s.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, r *http.Request) {
		id, err := Caller(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		sub, err := d.Hub.Subscribe(r.Context(), id.TenantID, id.UserID, r.Header.Get("Last-Event-ID"))
		if err != nil {
			if errors.Is(err, stream.ErrTooMany) {
				if d.Audit != nil {
					_ = d.Audit.Record(r.Context(), audit.Event{EventType: audit.StreamRefused, TenantID: id.TenantID, ActorKind: audit.ActorUser, ActorID: id.UserID, SubjectKind: audit.SubjectSystem, Outcome: audit.OutcomeRefused, Reason: "too_many_streams"})
				}
				Fail(w, r, nil, ErrRateLimited)
				return
			}
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		if d.Audit != nil {
			_ = d.Audit.Record(r.Context(), audit.Event{EventType: audit.StreamOpened, TenantID: id.TenantID, ActorKind: audit.ActorUser, ActorID: id.UserID, SubjectKind: audit.SubjectSystem, Outcome: audit.OutcomeOK, CorrelationID: RequestID(r)})
		}
		stream.ServeSSE(w, r, sub, instance, stream.Heartbeat, stream.MaxAge)
	})
}
