package contract

import (
	"strings"
	"testing"

	lcmv1 "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
)

// TestProtoServersImplemented proves the lcm.v1 servers satisfy the generated
// interfaces (SVID, Enrollment, Events, Agent) — the service-to-service and
// workload-agent surface.
func TestProtoServersImplemented(t *testing.T) {
	var _ lcmv1.SVIDServer = (*grpcapi.SVIDServer)(nil)
	var _ lcmv1.EnrollmentServer = (*grpcapi.EnrollmentServer)(nil)
	var _ lcmv1.EventsServer = (*grpcapi.EventsServer)(nil)
	var _ lcmv1.AgentServer = (*grpcapi.AgentServer)(nil)
}

// TestSSEFrameShape proves an SSE frame carries id, event and data lines and
// strips embedded newlines (contracts/stream.md).
func TestSSEFrameShape(t *testing.T) {
	f := stream.Frame(stream.Event{ID: "1700000000-0", Type: "renewed", Data: `{"certificate_id":"c1"}`})
	for _, want := range []string{"id: 1700000000-0", "event: renewed", "data: {\"certificate_id\":\"c1\"}"} {
		if !strings.Contains(f, want) {
			t.Errorf("frame missing %q:\n%s", want, f)
		}
	}
	if !strings.HasSuffix(f, "\n\n") {
		t.Errorf("frame must end with a blank line:\n%q", f)
	}
	// Embedded newlines in data must not break the frame protocol.
	inj := stream.Frame(stream.Event{ID: "x", Type: "issued", Data: "a\nb\nevent: forged"})
	if strings.Count(inj, "\ndata:") > 1 || strings.Contains(inj, "\nevent: forged") {
		t.Errorf("data newlines not neutralised:\n%q", inj)
	}
}
