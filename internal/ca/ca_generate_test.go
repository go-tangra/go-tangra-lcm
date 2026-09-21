package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/repo"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// TestGenerateDefensiveErrors drives every defensive error return in generate.
// The FIPS key generator and signer ignore the supplied reader for entropy, and
// marshalling/sealing a valid P-256 key do not fail in practice, so these paths
// are reached by replacing the crypto indirections rather than by a bad reader.
func TestGenerateDefensiveErrors(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()

	restore := func() {
		generateKey = ecdsa.GenerateKey
		createCertificate = x509.CreateCertificate
		marshalPrivateKey = x509.MarshalPKCS8PrivateKey
		sealKey = func(env *sealed.Envelope, plaintext, ad []byte) ([]byte, error) {
			return env.Seal(plaintext, ad)
		}
	}

	// Key generation failure.
	generateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, errBoom }
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("generateKey error want boom, got %v", err)
	}
	restore()

	// Certificate signing failure.
	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, errBoom
	}
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("createCertificate error want boom, got %v", err)
	}
	restore()

	// Private-key marshalling failure.
	marshalPrivateKey = func(any) ([]byte, error) { return nil, errBoom }
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("marshalPrivateKey error want boom, got %v", err)
	}
	restore()

	// Sealing failure.
	sealKey = func(*sealed.Envelope, []byte, []byte) ([]byte, error) { return nil, errBoom }
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("sealKey error want boom, got %v", err)
	}
	restore()
}

// TestGenerateBadTrustDomainURL calls generate directly with a trust domain
// that EnsureCA's validator would reject, so the url.Parse guard fires.
func TestGenerateBadTrustDomainURL(t *testing.T) {
	a, _ := newAuthority(t)
	if _, err := a.generate("t1", "\x7f"); !errors.Is(err, ErrInput) {
		t.Fatalf("url.Parse guard want ErrInput, got %v", err)
	}
}

// conflictThenErrStore forces InsertCA to conflict and then makes the
// post-conflict re-read fail, covering EnsureCA's conflict re-read error path.
type conflictThenErrStore struct {
	*memstore.Mem
	calls int
}

func (c *conflictThenErrStore) Atomic(_ context.Context, _ string, fn func(repo.Store) error) error {
	return fn(c)
}

func (c *conflictThenErrStore) CAByState(_ context.Context, _, _, _ string) (store.CA, error) {
	c.calls++
	if c.calls >= 3 { // fast-path miss, in-tx miss, then the post-conflict read errors
		return store.CA{}, errBoom
	}
	return store.CA{}, store.ErrNotFound
}

func (c *conflictThenErrStore) InsertCA(_ context.Context, _ store.CA) error {
	return store.ErrConflict
}

func TestEnsureCAConflictReReadError(t *testing.T) {
	cs := &conflictThenErrStore{Mem: memstore.New()}
	a := New(cs, newEnv(t))
	a.Clock = func() time.Time { return testNow }
	if _, err := a.EnsureCA(context.Background(), "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("conflict re-read error want boom, got %v", err)
	}
}
