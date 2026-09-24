package ca

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newEnv(t *testing.T) *sealed.Envelope {
	t.Helper()
	env, err := sealed.NewEnvelope(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env
}

func newAuthority(t *testing.T) (*Authority, *memstore.Mem) {
	t.Helper()
	mem := memstore.New()
	mem.Now = func() time.Time { return testNow }
	a := New(mem, newEnv(t))
	a.Clock = func() time.Time { return testNow }
	return a, mem
}

func TestEnsureCAGeneratesOnceAndReuses(t *testing.T) {
	a, mem := newAuthority(t)
	ctx := context.Background()

	ca1, err := a.EnsureCA(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if ca1.State != "active" || ca1.TrustDomain != "example.org" {
		t.Fatalf("unexpected CA: %+v", ca1)
	}
	if !ca1.NotBefore.Equal(testNow) {
		t.Fatalf("NotBefore = %v want %v", ca1.NotBefore, testNow)
	}
	if !ca1.NotAfter.Equal(testNow.Add(rootValidity)) {
		t.Fatalf("NotAfter = %v", ca1.NotAfter)
	}
	if len(mem.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(mem.CAs))
	}

	block, _ := pem.Decode([]byte(ca1.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatalf("root missing CA key usage: %+v", cert.KeyUsage)
	}
	if cert.Subject.CommonName != "example.org LCM Root" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.org" {
		t.Fatalf("URI SAN = %v", cert.URIs)
	}

	ca2, err := a.EnsureCA(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA reuse: %v", err)
	}
	if ca2.ID != ca1.ID {
		t.Fatalf("EnsureCA generated a second CA: %s != %s", ca2.ID, ca1.ID)
	}
	if len(mem.CAs) != 1 {
		t.Fatalf("expected still 1 CA, got %d", len(mem.CAs))
	}
}

func TestSignerSignsLeaf(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()
	caRow, err := a.EnsureCA(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	signer, caCert, err := a.Signer(ctx, caRow)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if !caCert.IsCA {
		t.Fatalf("expected CA cert")
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://example.org/workload")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    testNow,
		NotAfter:     testNow.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignLeafChainsToBundle(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, notAfter, err := a.SignLeaf(ctx, "t1", "example.org", "spiffe://example.org/svc/lcm", &key.PublicKey, time.Hour)
	if err != nil {
		t.Fatalf("SignLeaf: %v", err)
	}
	if !notAfter.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("notAfter = %v, want %v", notAfter, testNow.Add(time.Hour))
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if got := leaf.URIs[0].String(); got != "spiffe://example.org/svc/lcm" {
		t.Fatalf("URI SAN = %q", got)
	}
	// leaf must chain to the trust bundle (the one DB-sealed root).
	bundlePEM, err := a.Bundle(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundlePEM)) {
		t.Fatal("bundle has no roots")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify serverAuth: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify clientAuth: %v", err)
	}
}

func TestSignLeafRejectsBadInput(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// trust-domain mismatch between arg and SPIFFE id
	if _, _, err := a.SignLeaf(ctx, "t1", "example.org", "spiffe://evil.example/svc/lcm", &key.PublicKey, time.Hour); !errors.Is(err, ErrInput) {
		t.Fatalf("td mismatch err = %v, want ErrInput", err)
	}
	// non-positive ttl
	if _, _, err := a.SignLeaf(ctx, "t1", "example.org", "spiffe://example.org/svc/lcm", &key.PublicKey, 0); !errors.Is(err, ErrInput) {
		t.Fatalf("zero ttl err = %v, want ErrInput", err)
	}
}

func sealAs(t *testing.T, a *Authority, id string, plaintext []byte) []byte {
	t.Helper()
	blob, err := a.env.Seal(plaintext, sealed.ADCA(id))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return blob
}

func TestSignerErrors(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()

	// Tampered / unopenable sealed key.
	if _, _, err := a.Signer(ctx, store.CA{ID: "x", KeySealed: []byte("garbage")}); err == nil {
		t.Fatalf("expected open error")
	}

	// Sealed material that is not PEM.
	notPEM := store.CA{ID: "id1", KeySealed: sealAs(t, a, "id1", []byte("not pem at all"))}
	if _, _, err := a.Signer(ctx, notPEM); !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse, got %v", err)
	}

	// Valid PEM block but not a PKCS8 key.
	badKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nope")})
	badKey := store.CA{ID: "id2", KeySealed: sealAs(t, a, "id2", badKeyPEM)}
	if _, _, err := a.Signer(ctx, badKey); !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse for bad key, got %v", err)
	}

	// A PKCS8 key that is not a crypto.Signer (X25519 ECDH key).
	xkey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xDER, _ := x509.MarshalPKCS8PrivateKey(xkey)
	xPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: xDER})
	nonSigner := store.CA{ID: "id3", KeySealed: sealAs(t, a, "id3", xPEM)}
	if _, _, err := a.Signer(ctx, nonSigner); !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse for non-signer, got %v", err)
	}

	// Valid key, but bad certificate PEM.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	noCert := store.CA{ID: "id4", KeySealed: sealAs(t, a, "id4", keyPEM), CertPEM: "not a pem"}
	if _, _, err := a.Signer(ctx, noCert); !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse for missing cert PEM, got %v", err)
	}
	badCert := store.CA{ID: "id5", KeySealed: sealAs(t, a, "id5", keyPEM), CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))}
	if _, _, err := a.Signer(ctx, badCert); !errors.Is(err, ErrParse) {
		t.Fatalf("want ErrParse for bad cert, got %v", err)
	}
}

func TestBundleActiveAndRetiring(t *testing.T) {
	a, mem := newAuthority(t)
	ctx := context.Background()

	active, err := a.EnsureCA(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	// A retiring and a next CA, added directly.
	retiring := active
	retiring.ID = store.NewID()
	retiring.State = "retiring"
	retiring.CertPEM = "-----BEGIN CERTIFICATE-----\nRETIRING\n-----END CERTIFICATE-----\n"
	mem.CAs[retiring.ID] = retiring
	next := active
	next.ID = store.NewID()
	next.State = "next"
	next.CertPEM = "-----BEGIN CERTIFICATE-----\nNEXT\n-----END CERTIFICATE-----\n"
	mem.CAs[next.ID] = next

	bundle, err := a.Bundle(ctx, "t1", "example.org")
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if !bytes.Contains([]byte(bundle), []byte(active.CertPEM)) {
		t.Fatalf("bundle missing active root")
	}
	if !bytes.Contains([]byte(bundle), []byte("RETIRING")) {
		t.Fatalf("bundle missing retiring root")
	}
	if bytes.Contains([]byte(bundle), []byte("NEXT")) {
		t.Fatalf("bundle must exclude the next root")
	}
}

func TestEnsureCAValidation(t *testing.T) {
	a, _ := newAuthority(t)
	ctx := context.Background()
	if _, err := a.EnsureCA(ctx, "", "example.org"); !errors.Is(err, ErrInput) {
		t.Fatalf("empty tenant want ErrInput, got %v", err)
	}
	if _, err := a.EnsureCA(ctx, "t1", ""); !errors.Is(err, ErrInput) {
		t.Fatalf("empty domain want ErrInput, got %v", err)
	}
	if _, err := a.EnsureCA(ctx, "t1", "NOT VALID"); !errors.Is(err, ErrInput) {
		t.Fatalf("bad domain want ErrInput, got %v", err)
	}
}

var errBoom = errors.New("boom")

func TestEnsureCAStoreErrors(t *testing.T) {
	a, mem := newAuthority(t)
	ctx := context.Background()

	mem.FailOn("CAByState", errBoom)
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("fast-path error want boom, got %v", err)
	}
	mem.FailOn("CAByState", nil)

	mem.FailOn("InsertCA", errBoom)
	if _, err := a.EnsureCA(ctx, "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("insert error want boom, got %v", err)
	}
}

// conflictStore forces InsertCA to conflict and returns a winner CA on the
// post-conflict re-read, exercising the concurrency branch.
type conflictStore struct {
	*memstore.Mem
	won   store.CA
	calls int
}

func (c *conflictStore) Atomic(_ context.Context, _ string, fn func(repo.Store) error) error {
	return fn(c)
}

func (c *conflictStore) CAByState(_ context.Context, _, _, _ string) (store.CA, error) {
	c.calls++
	if c.calls >= 3 {
		return c.won, nil
	}
	return store.CA{}, store.ErrNotFound
}

func (c *conflictStore) InsertCA(_ context.Context, _ store.CA) error {
	return store.ErrConflict
}

func TestEnsureCAConflictReReads(t *testing.T) {
	won := store.CA{ID: "winner", TenantID: "t1", TrustDomain: "example.org", State: "active"}
	cs := &conflictStore{Mem: memstore.New(), won: won}
	a := New(cs, newEnv(t))
	a.Clock = func() time.Time { return testNow }
	got, err := a.EnsureCA(context.Background(), "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if got.ID != "winner" {
		t.Fatalf("expected winner CA, got %s", got.ID)
	}
}

func TestBundleStoreError(t *testing.T) {
	a, mem := newAuthority(t)
	mem.FailOn("CAsForDomain", errBoom)
	if _, err := a.Bundle(context.Background(), "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("want boom, got %v", err)
	}
}

// reReadStore returns NotFound on the fast path, then either a CA or an error on
// the in-transaction re-read, exercising both concurrency re-read branches.
type reReadStore struct {
	*memstore.Mem
	ca    store.CA
	reErr error
	calls int
}

func (r *reReadStore) Atomic(_ context.Context, _ string, fn func(repo.Store) error) error {
	return fn(r)
}

func (r *reReadStore) CAByState(_ context.Context, _, _, _ string) (store.CA, error) {
	r.calls++
	if r.calls == 1 {
		return store.CA{}, store.ErrNotFound
	}
	if r.reErr != nil {
		return store.CA{}, r.reErr
	}
	return r.ca, nil
}

func TestEnsureCARaceReReadFindsExisting(t *testing.T) {
	won := store.CA{ID: "raced", TenantID: "t1", TrustDomain: "example.org", State: "active"}
	rr := &reReadStore{Mem: memstore.New(), ca: won}
	a := New(rr, newEnv(t))
	a.Clock = func() time.Time { return testNow }
	got, err := a.EnsureCA(context.Background(), "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if got.ID != "raced" {
		t.Fatalf("expected raced CA, got %s", got.ID)
	}
}

func TestEnsureCAReReadError(t *testing.T) {
	rr := &reReadStore{Mem: memstore.New(), reErr: errBoom}
	a := New(rr, newEnv(t))
	a.Clock = func() time.Time { return testNow }
	if _, err := a.EnsureCA(context.Background(), "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("want boom, got %v", err)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errBoom }

func TestRandomSerialError(t *testing.T) {
	old := randReader
	randReader = failReader{}
	defer func() { randReader = old }()
	if _, err := randomSerial(); !errors.Is(err, errBoom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestGenerateEntropyError(t *testing.T) {
	a, _ := newAuthority(t)
	old := randReader
	randReader = failReader{}
	defer func() { randReader = old }()
	if _, err := a.EnsureCA(context.Background(), "t1", "example.org"); !errors.Is(err, errBoom) {
		t.Fatalf("want boom from generate, got %v", err)
	}
}

func TestNowDefaultsWhenClockNil(t *testing.T) {
	a, _ := newAuthority(t)
	a.Clock = nil
	ca, err := a.EnsureCA(context.Background(), "t1", "example.org")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if ca.NotBefore.IsZero() {
		t.Fatalf("expected a real not_before")
	}
}
