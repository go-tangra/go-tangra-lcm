package acme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const cfTestToken = "cf-secret-token-value"

// fakeCloudflare is a minimal Cloudflare v4 API: zones by name/id and TXT
// records create/delete. It fails requests without the bearer token.
type fakeCloudflare struct {
	mu       sync.Mutex
	zones    map[string]string // name -> id
	records  map[string]map[string]string
	nextID   int
	failWith string // when set, every call fails with this Cloudflare error message
	calls    []string
}

func newFakeCloudflare() *fakeCloudflare {
	return &fakeCloudflare{zones: map[string]string{"example.com": "zone-1"}, records: map[string]map[string]string{}}
}

func (f *fakeCloudflare) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer "+cfTestToken {
			cfWrite(w, http.StatusForbidden, false, nil, "Invalid request headers")
			return
		}
		if f.failWith != "" {
			cfWrite(w, http.StatusBadRequest, false, nil, f.failWith)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/client/v4")
		switch {
		case r.Method == http.MethodGet && path == "/zones":
			name := r.URL.Query().Get("name")
			var out []map[string]any
			if id, ok := f.zones[name]; ok {
				out = append(out, map[string]any{"id": id, "name": name, "name_servers": []string{"ns1.example.net", "ns2.example.net"}})
			}
			cfWrite(w, http.StatusOK, true, out, "")
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/zones/") && strings.Count(path, "/") == 2:
			id := strings.TrimPrefix(path, "/zones/")
			for name, zid := range f.zones {
				if zid == id {
					cfWrite(w, http.StatusOK, true, map[string]any{"id": id, "name": name, "name_servers": []string{"ns1.example.net"}}, "")
					return
				}
			}
			cfWrite(w, http.StatusNotFound, false, nil, "Could not route to /zones, perhaps your object identifier is invalid?")
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/dns_records"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode: %v", err)
			}
			if body["type"] != "TXT" {
				t.Errorf("record type %v", body["type"])
			}
			f.nextID++
			id := "rec-" + string(rune('0'+f.nextID))
			f.records[id] = map[string]string{"zone": strings.Split(path, "/")[2], "name": body["name"].(string), "content": body["content"].(string)}
			cfWrite(w, http.StatusOK, true, map[string]any{"id": id}, "")
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/dns_records"):
			var out []map[string]any
			for id, rec := range f.records {
				if rec["name"] == r.URL.Query().Get("name") && rec["content"] == r.URL.Query().Get("content") {
					out = append(out, map[string]any{"id": id})
				}
			}
			cfWrite(w, http.StatusOK, true, out, "")
		case r.Method == http.MethodDelete && strings.Contains(path, "/dns_records/"):
			id := path[strings.LastIndex(path, "/")+1:]
			delete(f.records, id)
			cfWrite(w, http.StatusOK, true, map[string]any{"id": id}, "")
		default:
			cfWrite(w, http.StatusNotFound, false, nil, "no route")
		}
	})
}

func cfWrite(w http.ResponseWriter, code int, ok bool, result any, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	var errs []map[string]any
	if msg != "" {
		errs = append(errs, map[string]any{"code": 9999, "message": msg})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": ok, "errors": errs, "result": result})
}

type propagationCall struct {
	fqdn, value string
	servers     []string
}

func newTestCloudflare(t *testing.T, f *fakeCloudflare, creds map[string]string) (*Cloudflare, *[]propagationCall) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	var waits []propagationCall
	cf, err := NewCloudflare(creds, CloudflareOptions{
		BaseURL: srv.URL + "/client/v4",
		HTTP:    srv.Client(),
		Propagation: func(_ context.Context, fqdn, value string, servers []string) {
			waits = append(waits, propagationCall{fqdn, value, servers})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cf, &waits
}

func TestCloudflarePresentAndCleanUpWithZoneLookup(t *testing.T) {
	f := newFakeCloudflare()
	cf, waits := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken})
	ctx := context.Background()
	if err := cf.Present(ctx, "www.example.com", "_acme-challenge.www.example.com", "txt-value"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 {
		t.Fatalf("records: %v", f.records)
	}
	for _, rec := range f.records {
		if rec["zone"] != "zone-1" || rec["name"] != "_acme-challenge.www.example.com" || rec["content"] != "txt-value" {
			t.Fatalf("record %v", rec)
		}
	}
	if len(*waits) != 1 || (*waits)[0].fqdn != "_acme-challenge.www.example.com" || (*waits)[0].value != "txt-value" || len((*waits)[0].servers) != 2 {
		t.Fatalf("propagation: %+v", *waits)
	}
	if err := cf.CleanUp(ctx, "www.example.com", "_acme-challenge.www.example.com", "txt-value"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 0 {
		t.Fatalf("record not removed: %v", f.records)
	}
	// www.example.com is tried before example.com.
	if !strings.Contains(f.calls[0], "name=www.example.com") || !strings.Contains(f.calls[1], "name=example.com") {
		t.Fatalf("zone lookup order: %v", f.calls)
	}
}

func TestCloudflareZoneIDSkipsLookup(t *testing.T) {
	f := newFakeCloudflare()
	cf, waits := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken, "zone_id": "zone-1"})
	if err := cf.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "GET /client/v4/zones?") {
			t.Fatalf("zone listed although zone_id is set: %v", f.calls)
		}
	}
	if len((*waits)[0].servers) != 1 {
		t.Fatalf("name servers of zone-1 not used: %+v", *waits)
	}
}

func TestCloudflareZoneIDWithoutZoneRead(t *testing.T) {
	// A token limited to DNS edit cannot read the zone: issuance still works,
	// propagation falls back to public resolvers (no name servers).
	f := newFakeCloudflare()
	cf, waits := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken, "zone_id": "zone-unknown"})
	if err := cf.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if len((*waits)[0].servers) != 0 {
		t.Fatalf("servers: %+v", *waits)
	}
}

func TestCloudflareCleanUpFindsRecordWithoutState(t *testing.T) {
	f := newFakeCloudflare()
	a, _ := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken})
	ctx := context.Background()
	if err := a.Present(ctx, "example.com", "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	// A second instance (e.g. after a restart) has no remembered record id.
	b, _ := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken})
	b.base = a.base
	b.hc = a.hc
	if err := b.CleanUp(ctx, "example.com", "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 0 {
		t.Fatalf("record not removed: %v", f.records)
	}
}

func TestCloudflareErrorsNameTheProblemNotTheToken(t *testing.T) {
	f := newFakeCloudflare()
	f.failWith = "Authentication error"
	cf, _ := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken, "zone_id": "zone-1"})
	err := cf.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), cfTestToken) {
		t.Fatal("token leaked in error")
	}
}

func TestCloudflareUnknownZone(t *testing.T) {
	f := newFakeCloudflare()
	cf, _ := newTestCloudflare(t, f, map[string]string{"api_token": cfTestToken})
	err := cf.Present(context.Background(), "other.org", "_acme-challenge.other.org", "v")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "no Cloudflare zone") {
		t.Fatalf("err = %v", err)
	}
}

func TestCloudflareWrongTokenRefused(t *testing.T) {
	f := newFakeCloudflare()
	cf, _ := newTestCloudflare(t, f, map[string]string{"api_token": "wrong"})
	err := cf.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "Invalid request headers") {
		t.Fatalf("err = %v", err)
	}
}

func TestCloudflareOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"success":true,"result":"`+strings.Repeat("a", maxCloudflareBody+10)+`"}`)
	}))
	defer srv.Close()
	cf, err := NewCloudflare(map[string]string{"api_token": cfTestToken, "zone_id": "z"}, CloudflareOptions{BaseURL: srv.URL, HTTP: srv.Client(), Propagation: func(context.Context, string, string, []string) {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cf.Present(context.Background(), "example.com", "_acme-challenge.example.com", "v"); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewCloudflareRequiresToken(t *testing.T) {
	if _, err := NewCloudflare(map[string]string{"zone_id": "z"}, CloudflareOptions{}); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewProviderWith("cloudflare", map[string]string{}, ProviderDeps{}); !errors.Is(err, ErrProvider) {
		t.Fatalf("registry err = %v", err)
	}
	p, err := NewProviderWith("cloudflare", map[string]string{"api_token": "t"}, ProviderDeps{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(*Cloudflare); !ok {
		t.Fatalf("provider %T", p)
	}
}

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("a.b.example.com.")
	want := []string{"a.b.example.com", "b.example.com", "example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
	if len(zoneCandidates("com")) != 0 {
		t.Fatal("a TLD is not a zone candidate")
	}
}

func TestWaitTXT(t *testing.T) {
	ctx := context.Background()
	n := 0
	lookup := func(context.Context, string) ([]string, error) {
		n++
		if n < 3 {
			return nil, errors.New("nxdomain")
		}
		return []string{"other", "want"}, nil
	}
	if !waitTXT(ctx, lookup, "_acme-challenge.example.com", "want", time.Millisecond, time.Second) {
		t.Fatal("value not seen")
	}
	if n != 3 {
		t.Fatalf("lookups = %d", n)
	}
	never := func(context.Context, string) ([]string, error) { return []string{"x"}, nil }
	if waitTXT(ctx, never, "f", "want", time.Millisecond, 20*time.Millisecond) {
		t.Fatal("timeout reported as seen")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if waitTXT(cctx, never, "f", "want", time.Millisecond, time.Second) {
		t.Fatal("cancelled wait reported as seen")
	}
}

func TestSupportedProviders(t *testing.T) {
	names := map[string]bool{}
	for _, p := range SupportedProviders() {
		names[p.Name] = true
		if !p.Supported {
			t.Fatalf("%s listed as unsupported", p.Name)
		}
	}
	for _, want := range []string{"cloudflare", "manual", FreyaDNS} {
		if !names[want] {
			t.Fatalf("%s missing: %v", want, names)
		}
	}
	if names["route53"] {
		t.Fatal("route53 has no adapter")
	}
	if !IsSupported("cloudflare") || IsSupported("route53") || IsSupported("") {
		t.Fatal("IsSupported")
	}
}

func TestSecretFieldKeys(t *testing.T) {
	keys := map[string]bool{}
	for _, k := range SecretFieldKeys() {
		keys[k] = true
	}
	for _, want := range []string{"api_token", "secret_access_key", "service_account_key", "auth_token", "api_key", "password"} {
		if !keys[want] {
			t.Fatalf("%s missing: %v", want, keys)
		}
	}
	for _, notSecret := range []string{"zone_id", "region", "username"} {
		if keys[notSecret] {
			t.Fatalf("%s is not secret", notSecret)
		}
	}
}
