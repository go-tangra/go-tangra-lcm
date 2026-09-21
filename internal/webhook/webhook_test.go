package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/memstore"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
)

const tenant = "11111111-1111-7111-8111-111111111111"

func newSvc(t *testing.T) (*Service, *memstore.Mem) {
	t.Helper()
	st := memstore.New()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	aw := audit.NewWriter(st, nil)
	t.Cleanup(aw.Close)
	s := New(st, env, aw, func() time.Time { return time.Unix(1700000000, 0) })
	s.backoff = time.Millisecond // keep retries fast in tests
	return s, st
}

func admin() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

func TestSign_StableAndMatchesIndependentHMAC(t *testing.T) {
	secret := []byte("s3cr3t")
	payload := []byte(`{"event":"certificate.issued"}`)

	got := Sign(secret, payload)
	if got != Sign(secret, payload) {
		t.Fatal("Sign is not stable")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("Sign mismatch: %s != %s", got, want)
	}
	if !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("missing prefix: %s", got)
	}
}

func TestCreate_ValidationAndSecretHidden(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t)

	// bad URL
	if _, err := s.Create(ctx, admin(), Input{Name: "x", URL: "ftp://nope", EventTypes: []string{EventIssued}}); err == nil {
		t.Fatal("non-http URL accepted")
	}
	// bad event
	if _, err := s.Create(ctx, admin(), Input{Name: "x", URL: "https://h/x", EventTypes: []string{"nope"}}); err == nil {
		t.Fatal("unknown event accepted")
	}
	// no events
	if _, err := s.Create(ctx, admin(), Input{Name: "x", URL: "https://h/x"}); err == nil {
		t.Fatal("empty events accepted")
	}

	v, err := s.Create(ctx, admin(), Input{Name: "hook", URL: "https://h/x", EventTypes: []string{EventIssued, EventFailed}, Secret: "MYSECRET"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !v.Enabled || v.URL != "https://h/x" || len(v.EventTypes) != 2 {
		t.Fatalf("bad view: %+v", v)
	}
	// secret never in the sealed blob as plaintext, nor in the view (View has no secret field at all).
	row := st.Webhooks[v.ID]
	if bytes.Contains(row.SecretSealed, []byte("MYSECRET")) {
		t.Fatal("plaintext secret found in sealed blob")
	}
	// name uniqueness
	if _, err := s.Create(ctx, admin(), Input{Name: "Hook", URL: "https://h/y", EventTypes: []string{EventIssued}}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	// generated secret when none supplied
	v2, err := s.Create(ctx, admin(), Input{Name: "gen", URL: "https://h/z", EventTypes: []string{EventRevoked}})
	if err != nil {
		t.Fatalf("create gen: %v", err)
	}
	if len(st.Webhooks[v2.ID].SecretSealed) == 0 {
		t.Fatal("generated secret not sealed")
	}
}

func TestDeliver_HeadersSignatureAndVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	const secret = "SIGNING-KEY"
	payload := []byte(`{"cert":"abc"}`)

	var gotEvent, gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEvent = r.Header.Get("X-LCM-Event")
		gotSig = r.Header.Get("X-LCM-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := s.Create(ctx, admin(), Input{Name: "h", URL: srv.URL, EventTypes: []string{EventIssued}, Secret: secret}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Deliver(ctx, tenant, EventIssued, payload); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if gotEvent != EventIssued {
		t.Fatalf("event header = %q", gotEvent)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("body mismatch: %q", gotBody)
	}
	// Verify the signature server-side with hmac.Equal.
	raw, ok := strings.CutPrefix(gotSig, "sha256=")
	if !ok {
		t.Fatalf("signature missing prefix: %q", gotSig)
	}
	gotMAC, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("bad hex sig: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		t.Fatal("signature does not verify")
	}
}

func TestDeliver_RetriesOn500ThenSucceeds(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := s.Create(ctx, admin(), Input{Name: "h", URL: srv.URL, EventTypes: []string{EventIssued}, Secret: "k"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Deliver(ctx, tenant, EventIssued, []byte("{}")); err != nil {
		t.Fatalf("deliver should succeed after retry: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 calls (500 then 200), got %d", got)
	}
}

func TestDeliver_GivesUpOn400(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	if _, err := s.Create(ctx, admin(), Input{Name: "h", URL: srv.URL, EventTypes: []string{EventFailed}, Secret: "SEEKRET"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	err := s.Deliver(ctx, tenant, EventFailed, []byte("{}"))
	if err == nil {
		t.Fatal("expected error on 4xx")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 call (no retry on 4xx), got %d", got)
	}
	// The secret must never appear in the error.
	if strings.Contains(err.Error(), "SEEKRET") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}

func TestDeliver_BoundsOversizePayload(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	big := make([]byte, MaxPayloadBytes+1)
	if err := s.Deliver(ctx, tenant, EventIssued, big); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestDeliver_DeadEndpointNoPanic(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	// Unroutable/closed address: transport error, retried and finally failed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now dead

	if _, err := s.Create(ctx, admin(), Input{Name: "dead", URL: url, EventTypes: []string{EventIssued}, Secret: "k"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Deliver(ctx, tenant, EventIssued, []byte("{}")); err == nil {
		t.Fatal("expected delivery error for dead endpoint")
	}
	// No subscribers for an unrelated event is a no-op success.
	if err := s.Deliver(ctx, tenant, EventRenewed, []byte("{}")); err != nil {
		t.Fatalf("no-subscriber deliver should be nil: %v", err)
	}
}

func FuzzSign(f *testing.F) {
	f.Add([]byte("key"), []byte("payload"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, secret, payload []byte) {
		got := Sign(secret, payload)
		if !strings.HasPrefix(got, "sha256=") {
			t.Fatalf("missing prefix: %q", got)
		}
		if got != Sign(secret, payload) {
			t.Fatal("not deterministic")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(payload)
		if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Fatalf("mismatch: %s != %s", got, want)
		}
	})
}

func TestListAndDelete(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t)
	v, err := s.Create(ctx, admin(), Input{Name: "h", URL: "https://h/x", EventTypes: []string{EventIssued}, Secret: "k"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	list, err := s.List(ctx, admin())
	if err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("list: %v n=%d", err, len(list))
	}
	if err := s.Delete(ctx, admin(), v.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := st.Webhooks[v.ID]; ok {
		t.Fatal("not deleted")
	}
	if err := s.Delete(ctx, admin(), v.ID); err == nil {
		t.Fatal("delete of missing webhook should error")
	}
	// error message shape
	ve := &ValidationError{Field: "url", Message: "bad"}
	if ve.Error() != "url: bad" {
		t.Fatalf("ValidationError.Error = %q", ve.Error())
	}
	ce := &ConflictError{Message: "dup"}
	if ce.Error() != "dup" {
		t.Fatalf("ConflictError.Error = %q", ce.Error())
	}
}
