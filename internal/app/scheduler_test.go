package app

import (
	"context"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"
)

// TestSchedulerCaller: only a verified peer of the service's own trust domain
// yields a service name for the executor's scheduler check.
func TestSchedulerCaller(t *testing.T) {
	caller := schedulerCaller("example.org")
	peer := func(td, name string) context.Context {
		id, err := identity.NewSPIFFEID(td, name)
		if err != nil {
			t.Fatal(err)
		}
		return authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id, ServiceName: name})
	}
	if svc, ok := caller(peer("example.org", "scheduler")); !ok || svc != "scheduler" {
		t.Fatalf("own domain = %q %v", svc, ok)
	}
	if svc, ok := caller(peer("evil.test", "scheduler")); ok || svc != "" {
		t.Fatalf("foreign domain = %q %v", svc, ok)
	}
	if svc, ok := caller(context.Background()); ok || svc != "" {
		t.Fatalf("no peer = %q %v", svc, ok)
	}
}
