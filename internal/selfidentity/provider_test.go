package selfidentity

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
)

func newCA(t *testing.T) *ca.Authority {
	t.Helper()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return ca.New(memstore.New(), env)
}

func TestProviderSelfIssuesAndChains(t *testing.T) {
	p, err := New(context.Background(), Config{CA: newCA(t), TenantID: "t1", TrustDomain: "example.org", ServiceName: "lcm", TTL: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	id, bnd, err := p.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got := id.ID().String(); got != "spiffe://example.org/svc/lcm" {
		t.Fatalf("id = %q", got)
	}
	if len(bnd.Roots()) == 0 {
		t.Fatal("empty bundle")
	}
	// the credential leaf must chain to the bundle roots.
	crt, err := p.Credential()
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if crt.PrivateKey == nil {
		t.Fatal("credential has no private key")
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	for _, r := range bnd.Roots() {
		roots.AddCert(r)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not chain to bundle: %v", err)
	}
}

func TestProviderRenewsBeforeExpiry(t *testing.T) {
	p, err := New(context.Background(), Config{CA: newCA(t), TenantID: "t1", TrustDomain: "example.org", ServiceName: "lcm", TTL: 300 * time.Millisecond, RenewBefore: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()
	id0, b0, _ := p.Current(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := p.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	select {
	case u := <-ch:
		if u.Err != nil {
			t.Fatalf("renew update error: %v", u.Err)
		}
		if u.Identity.Serial() == id0.Serial() {
			t.Fatal("serial did not change on renewal")
		}
		// The leaf rotates but the trust ROOT is unchanged, so the bundle
		// version MUST stay constant. Bumping it makes the framework treat a
		// leaf renewal as a bundle change and drain the outbound gRPC pool
		// (Pool.Rotate), which drops gateway registration and the auth verifier.
		if u.Bundle.Version() != b0.Version() {
			t.Fatalf("bundle version changed on leaf renewal: %d -> %d (roots unchanged)", b0.Version(), u.Bundle.Version())
		}
	case <-ctx.Done():
		t.Fatal("no renewal update before timeout")
	}
}
