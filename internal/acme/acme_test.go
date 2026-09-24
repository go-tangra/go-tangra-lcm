package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGenerateAccountKey(t *testing.T) {
	k, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey: %v", err)
	}
	if _, ok := k.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("account key is %T, want *ecdsa.PrivateKey", k)
	}
	if k.(*ecdsa.PrivateKey).Curve != elliptic.P256() {
		t.Fatal("account key is not P-256")
	}
}

func TestNewConfigValidation(t *testing.T) {
	key, _ := GenerateAccountKey()

	if _, err := New(Config{DNS: &NoopProvider{}}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing key: err = %v, want ErrConfig", err)
	}
	if _, err := New(Config{AccountKey: key}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing DNS: err = %v, want ErrConfig", err)
	}
	// AllowInsecure is refused against a non-loopback directory.
	_, err := New(Config{AccountKey: key, DNS: &NoopProvider{}, AllowInsecure: true, DirectoryURL: "https://acme.example.com/dir"})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("insecure+public: err = %v, want ErrConfig", err)
	}
	// AllowInsecure is permitted against loopback.
	if _, err := New(Config{AccountKey: key, DNS: &NoopProvider{}, AllowInsecure: true, DirectoryURL: "https://127.0.0.1:14000/dir"}); err != nil {
		t.Errorf("insecure+loopback: unexpected err %v", err)
	}
	// Defaults applied.
	c, err := New(Config{AccountKey: key, DNS: &NoopProvider{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.poll != DefaultPollInterval || c.limit != DefaultTimeout {
		t.Errorf("defaults not applied: poll=%v limit=%v", c.poll, c.limit)
	}
}

// TestObtainEndToEnd drives the full DNS-01 order flow against a minimal
// in-process fake ACME server, asserting the returned chain is non-empty PEM
// and that the DNS provider's Present and CleanUp both ran.
func TestObtainEndToEnd(t *testing.T) {
	ca := newFakeCA(t)
	srv := httptest.NewServer(ca)
	defer srv.Close()
	ca.baseURL = srv.URL

	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	dns := &NoopProvider{}
	client, err := New(Config{
		DirectoryURL: srv.URL + "/directory",
		AccountEmail: "ca@example.com",
		AccountKey:   key,
		DNS:          dns,
		PollInterval: 5 * time.Millisecond,
		Timeout:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := client.Register(ctx); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Register is idempotent.
	if err := client.Register(ctx); err != nil {
		t.Fatalf("Register (second): %v", err)
	}

	domains := []string{"example.com"}
	csrDER := makeCSR(t, domains)

	chainPEM, err := client.Obtain(ctx, csrDER, domains)
	if err != nil {
		t.Fatalf("Obtain: %v", err)
	}
	if chainPEM == "" {
		t.Fatal("Obtain returned an empty chain")
	}
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("chain is not a PEM CERTIFICATE: %.60q", chainPEM)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("chain does not parse as a certificate: %v", err)
	}

	calls := dns.Calls()
	var present, cleanup int
	for _, c := range calls {
		switch c.Op {
		case "present":
			present++
		case "cleanup":
			cleanup++
		}
		if c.FQDN != "_acme-challenge.example.com" {
			t.Errorf("unexpected challenge fqdn %q", c.FQDN)
		}
		if c.Value == "" {
			t.Error("challenge value was empty")
		}
	}
	if present != 1 || cleanup != 1 {
		t.Fatalf("provider calls: present=%d cleanup=%d, want 1/1", present, cleanup)
	}
}

func TestObtainRejectsBadInput(t *testing.T) {
	key, _ := GenerateAccountKey()
	client, _ := New(Config{AccountKey: key, DNS: &NoopProvider{}})
	ctx := context.Background()
	if _, err := client.Obtain(ctx, nil, []string{"a.com"}); !errors.Is(err, ErrOrder) {
		t.Errorf("empty CSR: err = %v, want ErrOrder", err)
	}
	if _, err := client.Obtain(ctx, []byte{1, 2, 3}, nil); !errors.Is(err, ErrOrder) {
		t.Errorf("no domains: err = %v, want ErrOrder", err)
	}
}

// --- helpers ---

func makeCSR(t *testing.T, domains []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeCA is a minimal RFC 8555 ACME server: just enough of the protocol
// (directory, new-nonce, new-account, new-order, one dns-01 authorization,
// challenge accept, finalize and cert download) to drive Obtain. It does not
// verify JWS signatures — it routes by path and method and always issues a
// Replay-Nonce so the client's nonce pool stays full.
type fakeCA struct {
	baseURL  string
	leafPEM  []byte
	mu       sync.Mutex
	accepted map[string]bool // authz path -> challenge accepted
	// override, when set for a request path, replaces the default handler so a
	// scenario can force a single phase of the flow to fail.
	override map[string]http.HandlerFunc
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCA{
		leafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		accepted: map[string]bool{},
	}
}

func (f *fakeCA) writeJSON(w http.ResponseWriter, status int, v any) {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	w.Header().Set("Replay-Nonce", fmt.Sprintf("%x", nonce))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (f *fakeCA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	base := f.baseURL
	if h := f.override[r.URL.Path]; h != nil {
		h(w, r)
		return
	}
	switch {
	case r.URL.Path == "/directory":
		f.writeJSON(w, http.StatusOK, map[string]string{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
			"revokeCert": base + "/revoke-cert",
			"keyChange":  base + "/key-change",
		})

	case r.URL.Path == "/new-nonce":
		f.writeJSON(w, http.StatusNoContent, nil)

	case r.URL.Path == "/new-account":
		w.Header().Set("Location", base+"/account/1")
		f.writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})

	case r.URL.Path == "/new-order":
		w.Header().Set("Location", base+"/order/1")
		f.writeJSON(w, http.StatusCreated, map[string]any{
			"status":         "pending",
			"identifiers":    []map[string]string{{"type": "dns", "value": "example.com"}},
			"authorizations": []string{base + "/authz/1"},
			"finalize":       base + "/order/1/finalize",
		})

	case r.URL.Path == "/authz/1":
		f.mu.Lock()
		valid := f.accepted["/authz/1"]
		f.mu.Unlock()
		status := "pending"
		if valid {
			status = "valid"
		}
		f.writeJSON(w, http.StatusOK, map[string]any{
			"status":     status,
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{
				"type":   "dns-01",
				"url":    base + "/chal/1",
				"token":  "test-token-1",
				"status": status,
			}},
		})

	case r.URL.Path == "/chal/1":
		f.mu.Lock()
		f.accepted["/authz/1"] = true
		f.mu.Unlock()
		f.writeJSON(w, http.StatusOK, map[string]any{
			"type": "dns-01", "url": base + "/chal/1", "token": "test-token-1", "status": "valid",
		})

	case r.URL.Path == "/order/1":
		f.mu.Lock()
		valid := f.accepted["/authz/1"]
		f.mu.Unlock()
		status := "pending"
		if valid {
			status = "ready"
		}
		w.Header().Set("Location", base+"/order/1")
		f.writeJSON(w, http.StatusOK, map[string]any{"status": status})

	case r.URL.Path == "/order/1/finalize":
		w.Header().Set("Location", base+"/order/1")
		f.writeJSON(w, http.StatusOK, map[string]any{
			"status":      "valid",
			"certificate": base + "/cert/1",
		})

	case r.URL.Path == "/cert/1":
		w.Header().Set("Replay-Nonce", "cert-nonce")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(f.leafPEM)

	default:
		http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
	}
}

// Guard: the scrub helper must never surface a raw acme.Error detail.
func TestScrubIsTerse(t *testing.T) {
	err := scrub(errors.New("boom with secret=abc123 detail"))
	if strings.Contains(err.Error(), "abc123") {
		t.Fatalf("scrub leaked detail: %v", err)
	}
}
