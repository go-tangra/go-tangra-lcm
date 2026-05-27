package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestProvider builds a challengeProvider whose Cloudflare client targets the
// given test server. The embedded lego provider is nil because orphan cleanup
// never touches it.
func newTestProvider(baseURL string) *challengeProvider {
	return &challengeProvider{
		client: &cfClient{
			httpClient: &http.Client{Timeout: 5 * time.Second},
			baseURL:    baseURL,
			zoneToken:  "zone-token",
			dnsToken:   "dns-token",
		},
	}
}

func TestCleanupOrphanedChallengeRecords_DeletesAllMatching(t *testing.T) {
	var mu sync.Mutex
	deleted := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			// Walk down: only the registrable domain "factory.bg" is a zone.
			if r.URL.Query().Get("name") == "factory.bg" {
				writeJSON(w, `{"success":true,"errors":[],"result":[{"id":"zone123","name":"factory.bg"}]}`)
			} else {
				writeJSON(w, `{"success":true,"errors":[],"result":[]}`)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone123/dns_records":
			if r.URL.Query().Get("type") != "TXT" ||
				r.URL.Query().Get("name") != "_acme-challenge.factory.bg" {
				t.Errorf("unexpected record query: %s", r.URL.RawQuery)
			}
			writeJSON(w, `{"success":true,"errors":[],"result":[
				{"id":"rec-A","name":"_acme-challenge.factory.bg","type":"TXT"},
				{"id":"rec-B","name":"_acme-challenge.factory.bg","type":"TXT"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone123/dns_records/")
			mu.Lock()
			deleted[id] = true
			mu.Unlock()
			writeJSON(w, `{"success":true,"errors":[],"result":{"id":"`+id+`"}}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	p := newTestProvider(srv.URL)
	if err := p.CleanupOrphanedChallengeRecords(context.Background(), "_acme-challenge.factory.bg"); err != nil {
		t.Fatalf("CleanupOrphanedChallengeRecords: %v", err)
	}

	if !deleted["rec-A"] || !deleted["rec-B"] {
		t.Errorf("expected both records deleted, got %v", deleted)
	}
}

func TestCleanupOrphanedChallengeRecords_NoRecordsIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "factory.bg" {
				writeJSON(w, `{"success":true,"errors":[],"result":[{"id":"zone123","name":"factory.bg"}]}`)
			} else {
				writeJSON(w, `{"success":true,"errors":[],"result":[]}`)
			}
		case r.URL.Path == "/zones/zone123/dns_records":
			writeJSON(w, `{"success":true,"errors":[],"result":[]}`)
		default:
			if r.Method == http.MethodDelete {
				t.Errorf("delete should not be called when no records exist: %s", r.URL.Path)
			}
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	p := newTestProvider(srv.URL)
	if err := p.CleanupOrphanedChallengeRecords(context.Background(), "_acme-challenge.factory.bg"); err != nil {
		t.Fatalf("expected no error for empty record set, got %v", err)
	}
}

func TestCleanupOrphanedChallengeRecords_APIErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}],"result":null}`)
	}))
	defer srv.Close()

	p := newTestProvider(srv.URL)
	err := p.CleanupOrphanedChallengeRecords(context.Background(), "_acme-challenge.factory.bg")
	if err == nil {
		t.Fatal("expected error when zone lookup is unauthorized")
	}
	if !strings.Contains(err.Error(), "locate zone") {
		t.Errorf("expected zone-lookup error, got %v", err)
	}
}

func TestCleanupOrphanedChallengeRecords_RefusesNonChallengeName(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not be reached", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := newTestProvider(srv.URL)
	// An apex name (where SPF/DKIM live) must be refused outright.
	err := p.CleanupOrphanedChallengeRecords(context.Background(), "factory.bg")
	if err == nil {
		t.Fatal("expected refusal for non-challenge name")
	}
	if !strings.Contains(err.Error(), "refusing to clean non-challenge name") {
		t.Errorf("unexpected error: %v", err)
	}
	if called {
		t.Error("no API call should be made when the name is refused")
	}
}

// TestCleanupOrphanedChallengeRecords_SkipsForeignRecords ensures that if the
// API ever returns records other than the exact challenge TXT (e.g. an SPF
// record or a CNAME), they are never deleted.
func TestCleanupOrphanedChallengeRecords_SkipsForeignRecords(t *testing.T) {
	var mu sync.Mutex
	deleted := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "factory.bg" {
				writeJSON(w, `{"success":true,"errors":[],"result":[{"id":"zone123","name":"factory.bg"}]}`)
			} else {
				writeJSON(w, `{"success":true,"errors":[],"result":[]}`)
			}
		case r.URL.Path == "/zones/zone123/dns_records":
			// Deliberately mixed payload: only "rec-challenge" is eligible.
			writeJSON(w, `{"success":true,"errors":[],"result":[
				{"id":"rec-challenge","name":"_acme-challenge.factory.bg","type":"TXT"},
				{"id":"rec-spf","name":"factory.bg","type":"TXT"},
				{"id":"rec-cname","name":"_acme-challenge.factory.bg","type":"CNAME"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone123/dns_records/")
			mu.Lock()
			deleted[id] = true
			mu.Unlock()
			writeJSON(w, `{"success":true,"errors":[],"result":{"id":"`+id+`"}}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer srv.Close()

	p := newTestProvider(srv.URL)
	if err := p.CleanupOrphanedChallengeRecords(context.Background(), "_acme-challenge.factory.bg"); err != nil {
		t.Fatalf("CleanupOrphanedChallengeRecords: %v", err)
	}

	if !deleted["rec-challenge"] {
		t.Error("the exact challenge TXT record should have been deleted")
	}
	if deleted["rec-spf"] {
		t.Error("SPF record at apex must never be deleted")
	}
	if deleted["rec-cname"] {
		t.Error("non-TXT record must never be deleted")
	}
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}
