package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const gcTestAccessToken = "ya29.test-access-token"

// fakeGoogle is Google's token endpoint (it verifies the signed assertion)
// and a minimal Cloud DNS v1: managed zones, TXT record sets and changes that
// must delete the current set exactly, as the real API requires.
type fakeGoogle struct {
	t   *testing.T
	pub *rsa.PublicKey

	mu        sync.Mutex
	zones     []gcZone
	rrsets    map[string]gcRRSet // zone + " " + name
	tokens    int
	conflicts int    // the next n changes fail with 412
	failWith  string // every DNS call fails with this message (HTTP 403)
	pending   bool   // changes start pending and are done on the first poll
	calls     []string
	tokenURL  string
}

func newFakeGoogle(t *testing.T) (*fakeGoogle, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj-1", "private_key_id": "kid-1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "lcm-dns@proj-1.iam.gserviceaccount.com", "token_uri": "https://attacker.invalid/token",
	})
	f := &fakeGoogle{t: t, pub: &key.PublicKey, rrsets: map[string]gcRRSet{}, zones: []gcZone{
		{Name: "example-com", DNSName: "example.com.", NameServers: []string{"ns-cloud-a1.googledomains.com."}, Visibility: "public"},
		{Name: "internal-example-org", DNSName: "example.org.", Visibility: "private"},
	}}
	return f, string(sa)
}

func gcErr(msg, status string) map[string]any {
	return map[string]any{"error": map[string]any{"message": msg, "status": status}}
}

func (f *fakeGoogle) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/token" {
			f.token(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+gcTestAccessToken {
			gcWrite(w, http.StatusUnauthorized, gcErr("Request had invalid authentication credentials.", "UNAUTHENTICATED"))
			return
		}
		if f.failWith != "" {
			gcWrite(w, http.StatusForbidden, gcErr(f.failWith, "PERMISSION_DENIED"))
			return
		}
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/dns/v1/projects/proj-1/managedZones"), "/")
		switch {
		case r.Method == http.MethodGet && len(p) == 1 && p[0] == "":
			var out []gcZone
			for _, z := range f.zones {
				if z.DNSName == r.URL.Query().Get("dnsName") {
					out = append(out, z)
				}
			}
			gcWrite(w, http.StatusOK, map[string]any{"managedZones": out})
		case r.Method == http.MethodGet && len(p) == 2:
			for _, z := range f.zones {
				if z.Name == p[1] {
					gcWrite(w, http.StatusOK, z)
					return
				}
			}
			gcWrite(w, http.StatusNotFound, gcErr("The 'parameters.managedZone' resource named '"+p[1]+"' does not exist.", "NOT_FOUND"))
		case r.Method == http.MethodGet && len(p) == 3 && p[2] == "rrsets":
			var out []gcRRSet
			if rs, ok := f.rrsets[p[1]+" "+r.URL.Query().Get("name")]; ok && r.URL.Query().Get("type") == "TXT" {
				out = append(out, rs)
			}
			gcWrite(w, http.StatusOK, map[string]any{"rrsets": out})
		case r.Method == http.MethodPost && len(p) == 3 && p[2] == "changes":
			if f.conflicts > 0 {
				f.conflicts--
				gcWrite(w, http.StatusPreconditionFailed, gcErr("Precondition not met for 'entity.change.deletions[0]'", "FAILED_PRECONDITION"))
				return
			}
			var ch map[string][]gcRRSet
			if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
				f.t.Errorf("decode change: %v", err)
			}
			for _, d := range ch["deletions"] {
				if cur, ok := f.rrsets[p[1]+" "+d.Name]; !ok || !reflect.DeepEqual(cur, d) {
					gcWrite(w, http.StatusPreconditionFailed, gcErr("Precondition not met", "FAILED_PRECONDITION"))
					return
				}
			}
			for _, d := range ch["deletions"] {
				delete(f.rrsets, p[1]+" "+d.Name)
			}
			for _, a := range ch["additions"] {
				if _, ok := f.rrsets[p[1]+" "+a.Name]; ok {
					gcWrite(w, http.StatusConflict, gcErr("already exists", "ALREADY_EXISTS"))
					return
				}
				f.rrsets[p[1]+" "+a.Name] = a
			}
			status := "done"
			if f.pending {
				status = "pending"
			}
			gcWrite(w, http.StatusOK, map[string]any{"id": "7", "status": status})
		case r.Method == http.MethodGet && len(p) == 4 && p[2] == "changes":
			gcWrite(w, http.StatusOK, map[string]any{"id": p[3], "status": "done"})
		default:
			gcWrite(w, http.StatusNotFound, gcErr("no route", ""))
		}
	})
}

// token checks the RFC 7523 assertion: grant type, RS256 signature by the
// key, issuer, audience (lcm's token URL, never the key's token_uri) and scope.
func (f *fakeGoogle) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	refuse := func(msg string) {
		gcWrite(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": msg})
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		refuse("grant_type")
		return
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if len(parts) != 3 {
		refuse("malformed")
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) != nil {
		refuse("Invalid JWT Signature.")
		return
	}
	var hdr, claims map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(h, &hdr)
	_ = json.Unmarshal(c, &claims)
	if hdr["alg"] != "RS256" || hdr["kid"] != "kid-1" || claims["iss"] != "lcm-dns@proj-1.iam.gserviceaccount.com" ||
		claims["aud"] != f.tokenURL || claims["scope"] != googleDNSScope {
		refuse("claims")
		return
	}
	f.tokens++
	gcWrite(w, http.StatusOK, map[string]any{"access_token": gcTestAccessToken, "expires_in": 3599, "token_type": "Bearer"})
}

func gcWrite(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func newTestGCloud(t *testing.T, f *fakeGoogle, creds map[string]string, now func() time.Time) (*GCloud, *[]propagationCall) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	f.tokenURL = srv.URL + "/token"
	var waits []propagationCall
	g, err := NewGCloud(creds, GCloudOptions{
		BaseURL: srv.URL + "/dns/v1", TokenURL: f.tokenURL, HTTP: srv.Client(), Now: now, PollEvery: time.Millisecond,
		Propagation: func(_ context.Context, fqdn, value string, servers []string) {
			waits = append(waits, propagationCall{fqdn, value, servers})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, &waits
}

func (f *fakeGoogle) txt(zone, name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs, ok := f.rrsets[zone+" "+name]
	if !ok {
		return nil
	}
	return rs.RRDatas
}

func TestGCloudPresentAndCleanUp(t *testing.T) {
	f, sa := newFakeGoogle(t)
	g, waits := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, nil)
	ctx := context.Background()
	const fqdn, name = "_acme-challenge.www.example.com", "_acme-challenge.www.example.com."

	if err := g.Present(ctx, "www.example.com", fqdn, "v1"); err != nil {
		t.Fatal(err)
	}
	if got := f.txt("example-com", name); !reflect.DeepEqual(got, []string{`"v1"`}) {
		t.Fatalf("TXT after present: %v", got)
	}
	if len(*waits) != 1 || (*waits)[0].fqdn != fqdn || (*waits)[0].servers[0] != "ns-cloud-a1.googledomains.com." {
		t.Fatalf("propagation: %+v", *waits)
	}
	// A wildcard order shares the name: both values are kept, then removed one
	// by one; repeating a call changes nothing.
	for range 2 {
		if err := g.Present(ctx, "www.example.com", fqdn, "v2"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.txt("example-com", name); !reflect.DeepEqual(got, []string{`"v1"`, `"v2"`}) {
		t.Fatalf("TXT after second present: %v", got)
	}
	if err := g.CleanUp(ctx, "www.example.com", fqdn, "v1"); err != nil {
		t.Fatal(err)
	}
	if got := f.txt("example-com", name); !reflect.DeepEqual(got, []string{`"v2"`}) {
		t.Fatalf("TXT after first cleanup: %v", got)
	}
	for range 2 {
		if err := g.CleanUp(ctx, "www.example.com", fqdn, "v2"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.txt("example-com", name); got != nil {
		t.Fatalf("TXT after cleanup: %v", got)
	}
	if f.tokens != 1 {
		t.Fatalf("access token requested %d times, want 1 (cached)", f.tokens)
	}
}

func TestGCloudTokenRefreshedWhenExpired(t *testing.T) {
	f, sa := newFakeGoogle(t)
	now := time.Now()
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, func() time.Time { return now })
	ctx := context.Background()
	if err := g.Present(ctx, "example.com", "_acme-challenge.example.com", "a"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := g.CleanUp(ctx, "example.com", "_acme-challenge.example.com", "a"); err != nil {
		t.Fatal(err)
	}
	if f.tokens != 2 {
		t.Fatalf("tokens %d, want 2", f.tokens)
	}
}

func TestGCloudManagedZoneSkipsLookupAndPollsPendingChange(t *testing.T) {
	f, sa := newFakeGoogle(t)
	f.pending = true
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa, "managed_zone": "example-com"}, nil)
	if err := g.Present(context.Background(), "a.b.example.com", "_acme-challenge.a.b.example.com", "x"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n") + "\n"
	if strings.Contains(joined, "GET /dns/v1/projects/proj-1/managedZones\n") {
		t.Fatalf("zones listed although managed_zone is set:\n%s", joined)
	}
	if !strings.Contains(joined, "GET /dns/v1/projects/proj-1/managedZones/example-com/changes/7\n") {
		t.Fatalf("pending change not polled:\n%s", joined)
	}
}

func TestGCloudUnknownManagedZone(t *testing.T) {
	f, sa := newFakeGoogle(t)
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa, "managed_zone": "nope"}, nil)
	err := g.Present(context.Background(), "example.com", "_acme-challenge.example.com", "x")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "'nope' does not exist") {
		t.Fatalf("err = %v", err)
	}
}

func TestGCloudRetriesConflictingChange(t *testing.T) {
	f, sa := newFakeGoogle(t)
	f.conflicts = gcloudAttempts - 1
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, nil)
	if err := g.Present(context.Background(), "example.com", "_acme-challenge.example.com", "x"); err != nil {
		t.Fatal(err)
	}
	f.conflicts = gcloudAttempts
	err := g.Present(context.Background(), "example.com", "_acme-challenge.example.com", "y")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("err = %v", err)
	}
}

func TestGCloudSkipsPrivateZones(t *testing.T) {
	f, sa := newFakeGoogle(t)
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, nil)
	err := g.Present(context.Background(), "www.example.org", "_acme-challenge.www.example.org", "x")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "no public Cloud DNS zone for www.example.org in project proj-1") {
		t.Fatalf("err = %v", err)
	}
}

func TestGCloudErrorsNameTheProblemNotTheSecrets(t *testing.T) {
	f, sa := newFakeGoogle(t)
	f.failWith = "Forbidden: caller lacks dns.changes.create; token " + gcTestAccessToken
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, nil)
	err := g.Present(context.Background(), "example.com", "_acme-challenge.example.com", "x")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "lacks dns.changes.create") || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), gcTestAccessToken) || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("secret in error: %v", err)
	}
}

func TestGCloudRefusedKey(t *testing.T) {
	f, sa := newFakeGoogle(t)
	g, _ := newTestGCloud(t, f, map[string]string{"service_account_key": sa}, nil)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.pub = &other.PublicKey // the key was deleted in Google: signatures no longer verify
	err = g.Present(context.Background(), "example.com", "_acme-challenge.example.com", "x")
	if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "lcm-dns@proj-1.iam.gserviceaccount.com refused") || !strings.Contains(err.Error(), "Invalid JWT Signature") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewGCloudCredentials(t *testing.T) {
	_, sa := newFakeGoogle(t)
	g, err := NewGCloud(map[string]string{"service_account_key": base64.StdEncoding.EncodeToString([]byte(sa)), "project": " other-proj "}, GCloudOptions{})
	if err != nil {
		t.Fatalf("base64 key: %v", err)
	}
	// The key's token_uri is never used.
	if g.project != "other-proj" || g.tokenURL != GoogleTokenURL || g.base != GoogleDNSAPI {
		t.Fatalf("project %q, token URL %q, base %q", g.project, g.tokenURL, g.base)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(sa), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "project_id")
	noProject, _ := json.Marshal(m)
	user, _ := json.Marshal(map[string]string{"type": "authorized_user", "client_id": "x"})
	badKey, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "a@b", "private_key": "not a key"})
	for name, tc := range map[string]struct {
		creds map[string]string
		want  string
	}{
		"missing":    {map[string]string{}, "service_account_key is required"},
		"not json":   {map[string]string{"service_account_key": "{nope"}, "not a JSON key file"},
		"user creds": {map[string]string{"service_account_key": string(user)}, "must be a service account key"},
		"bad key":    {map[string]string{"service_account_key": string(badKey)}, "not an RSA private key"},
		"no project": {map[string]string{"service_account_key": string(noProject)}, "project is required"},
	} {
		_, err := NewProvider("gcloud", tc.creds)
		if !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: key material in error", name)
		}
	}
	if p, err := NewProvider("gcloud", map[string]string{"service_account_key": sa}); err != nil || p == nil {
		t.Fatalf("registry: %v", err)
	}
}
