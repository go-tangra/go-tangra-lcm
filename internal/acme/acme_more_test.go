package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// --- small unit tests for the pure helpers ---

func TestDescribeClassifies(t *testing.T) {
	ae := describe(&xacme.Error{ProblemType: "urn:ietf:params:acme:error:malformed", Detail: "secret=abc"})
	if !containsSub(ae, "malformed") || containsSub(ae, "secret=abc") {
		t.Fatalf("acme error describe: %v", ae)
	}
	ne := describe(&net.DNSError{Err: "no such host", Name: "acme.example"})
	if !containsSub(ne, "network error") {
		t.Fatalf("net error describe: %v", ne)
	}
	g := describe(errors.New("plain boom"))
	if containsSub(g, "boom") {
		t.Fatalf("generic describe leaked: %v", g)
	}
}

func containsSub(s, sub string) bool { return indexOf(s, sub) >= 0 }

func TestWrapTimeoutAndJoin(t *testing.T) {
	// Deadline/cancel causes collapse to ErrTimeout.
	if err := wrap(context.Background(), ErrOrder, context.DeadlineExceeded); !errors.Is(err, ErrTimeout) {
		t.Fatalf("deadline cause: %v", err)
	}
	if err := wrap(context.Background(), ErrOrder, context.Canceled); !errors.Is(err, ErrTimeout) {
		t.Fatalf("cancel cause: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := wrap(cancelled, ErrOrder, errors.New("x")); !errors.Is(err, ErrTimeout) {
		t.Fatalf("cancelled ctx: %v", err)
	}
	// A live context with an ordinary cause is the sentinel with a description.
	if err := wrap(context.Background(), ErrChallenge, errors.New("x")); !errors.Is(err, ErrChallenge) {
		t.Fatalf("join: %v", err)
	}
}

func TestIsLoopbackDirectory(t *testing.T) {
	if isLoopbackDirectory("") {
		t.Fatal("empty URL is not loopback")
	}
	// "localhost" host with no scheme and no path: exercises the localhost
	// branch plus indexOf/indexByte "not found" returns.
	if !isLoopbackDirectory("localhost") {
		t.Fatal("localhost must be loopback")
	}
	if !isLoopbackDirectory("http://localhost/dir") {
		t.Fatal("http://localhost/dir must be loopback")
	}
	if !isLoopbackDirectory("https://127.0.0.1:14000/dir") {
		t.Fatal("127.0.0.1 must be loopback")
	}
	if isLoopbackDirectory("https://acme.example.com/dir") {
		t.Fatal("public host is not loopback")
	}
}

func TestDNS01ChallengeSelects(t *testing.T) {
	if dns01Challenge(nil) != nil {
		t.Fatal("empty set: want nil")
	}
	chals := []*xacme.Challenge{nil, {Type: "http-01"}, {Type: "dns-01", Token: "t"}}
	got := dns01Challenge(chals)
	if got == nil || got.Type != "dns-01" {
		t.Fatalf("select dns-01: %v", got)
	}
	if dns01Challenge([]*xacme.Challenge{{Type: "http-01"}}) != nil {
		t.Fatal("no dns-01: want nil")
	}
}

// --- Obtain error-path scenarios against the fake CA ---

func newScenario(t *testing.T) (*fakeCA, *xacme.Client, *Client, *NoopProvider) {
	t.Helper()
	ca := newFakeCA(t)
	ca.override = map[string]http.HandlerFunc{}
	srv := httptest.NewServer(ca)
	t.Cleanup(srv.Close)
	ca.baseURL = srv.URL
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	dns := &NoopProvider{}
	c, err := New(Config{
		DirectoryURL: srv.URL + "/directory",
		AccountKey:   key,
		DNS:          dns,
		PollInterval: 2 * time.Millisecond,
		Timeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return ca, c.ac, c, dns
}

// acmeReject writes a terse ACME problem so the client fails the phase.
func acmeReject(w http.ResponseWriter, _ *http.Request) {
	var nonce [16]byte
	w.Header().Set("Replay-Nonce", fmt.Sprintf("%x", nonce[:]))
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:ietf:params:acme:error:malformed", "detail": "rejected",
	})
}

func TestRegisterError(t *testing.T) {
	ca := newFakeCA(t)
	ca.override = map[string]http.HandlerFunc{"/new-account": acmeReject}
	srv := httptest.NewServer(ca)
	defer srv.Close()
	ca.baseURL = srv.URL
	key, _ := GenerateAccountKey()
	c, err := New(Config{DirectoryURL: srv.URL + "/directory", AccountEmail: "ca@example.com", AccountKey: key, DNS: &NoopProvider{}, PollInterval: time.Millisecond, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Register(context.Background()); !errors.Is(err, ErrOrder) {
		t.Fatalf("Register error: want ErrOrder, got %v", err)
	}
}

func TestObtainAuthorizeOrderError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	ca.override["/new-order"] = acmeReject
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrOrder) {
		t.Fatalf("authorize order error: want ErrOrder, got %v", err)
	}
}

func TestObtainGetAuthorizationError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	ca.override["/authz/1"] = acmeReject
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("get authorization error: want ErrChallenge, got %v", err)
	}
}

func TestObtainReusedAuthorizationContinues(t *testing.T) {
	ca, _, c, dns := newScenario(t)
	base := ca.baseURL
	// Authorization already valid: the loop skips the challenge entirely.
	ca.override["/authz/1"] = func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{"type": "dns-01", "url": base + "/chal/1", "token": "t", "status": "valid"}},
		})
	}
	ca.override["/order/1"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", base+"/order/1")
		ca.writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	}
	csr := makeCSR(t, []string{"example.com"})
	chain, err := c.Obtain(context.Background(), csr, []string{"example.com"})
	if err != nil {
		t.Fatalf("reused authorization: %v", err)
	}
	if chain == "" {
		t.Fatal("empty chain")
	}
	if len(dns.Calls()) != 0 {
		t.Fatalf("valid authz should not touch DNS: %v", dns.Calls())
	}
}

func TestObtainNoDNS01Challenge(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	base := ca.baseURL
	ca.override["/authz/1"] = func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{"type": "http-01", "url": base + "/chal/1", "token": "t", "status": "pending"}},
		})
	}
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("no dns-01: want ErrChallenge, got %v", err)
	}
}

func TestObtainDNS01RecordError(t *testing.T) {
	_, _, c, _ := newScenario(t)
	orig := dns01Record
	dns01Record = func(*xacme.Client, string) (string, error) { return "", errors.New("bad key") }
	defer func() { dns01Record = orig }()
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("dns01 record error: want ErrChallenge, got %v", err)
	}
}

func TestObtainPresentError(t *testing.T) {
	ca := newFakeCA(t)
	ca.override = map[string]http.HandlerFunc{}
	srv := httptest.NewServer(ca)
	defer srv.Close()
	ca.baseURL = srv.URL
	key, _ := GenerateAccountKey()
	dns := &failPresentProvider{}
	c, err := New(Config{DirectoryURL: srv.URL + "/directory", AccountKey: key, DNS: dns, PollInterval: time.Millisecond, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrProvider) {
		t.Fatalf("present error: want ErrProvider, got %v", err)
	}
}

func TestObtainAcceptError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	ca.override["/chal/1"] = acmeReject
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("accept error: want ErrChallenge, got %v", err)
	}
}

func TestObtainWaitAuthorizationError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	base := ca.baseURL
	// A pending dns-01 challenge to work on, but the authorization itself is
	// invalid: GetAuthorization proceeds, WaitAuthorization then fails.
	ca.override["/authz/1"] = func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     "invalid",
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{"type": "dns-01", "url": base + "/chal/1", "token": "t", "status": "pending"}},
		})
	}
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("wait authorization error: want ErrChallenge, got %v", err)
	}
}

func TestObtainWaitOrderError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	base := ca.baseURL
	ca.override["/authz/1"] = func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{"type": "dns-01", "url": base + "/chal/1", "token": "t", "status": "valid"}},
		})
	}
	ca.override["/order/1"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", base+"/order/1")
		ca.writeJSON(w, http.StatusOK, map[string]any{"status": "invalid"})
	}
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrOrder) {
		t.Fatalf("wait order error: want ErrOrder, got %v", err)
	}
}

func TestObtainCreateOrderCertError(t *testing.T) {
	ca, _, c, _ := newScenario(t)
	base := ca.baseURL
	ca.override["/authz/1"] = func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     "valid",
			"identifier": map[string]string{"type": "dns", "value": "example.com"},
			"challenges": []map[string]any{{"type": "dns-01", "url": base + "/chal/1", "token": "t", "status": "valid"}},
		})
	}
	ca.override["/order/1"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", base+"/order/1")
		ca.writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	}
	ca.override["/order/1/finalize"] = acmeReject
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrOrder) {
		t.Fatalf("create order cert error: want ErrOrder, got %v", err)
	}
}

func TestObtainEmptyChain(t *testing.T) {
	_, _, c, _ := newScenario(t)
	orig := createOrderCert
	createOrderCert = func(*xacme.Client, context.Context, string, []byte, bool) ([][]byte, string, error) {
		return [][]byte{}, "", nil
	}
	defer func() { createOrderCert = orig }()
	csr := makeCSR(t, []string{"example.com"})
	if _, err := c.Obtain(context.Background(), csr, []string{"example.com"}); !errors.Is(err, ErrOrder) {
		t.Fatalf("empty chain: want ErrOrder, got %v", err)
	}
}

// failPresentProvider fails Present but otherwise records like NoopProvider so
// deferred cleanup still runs.
type failPresentProvider struct{ NoopProvider }

func (p *failPresentProvider) Present(_ context.Context, _, _, _ string) error {
	return errors.New("dns backend unavailable")
}
