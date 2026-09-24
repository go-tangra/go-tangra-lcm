package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/revoke"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stats"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/transfer"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/webhook"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

const (
	apiTenant = "11111111-1111-7111-8111-111111111111"
	apiAdmin  = "22222222-2222-7222-8222-222222222222"
	apiBob    = "33333333-3333-7333-8333-333333333333"
)

// fakeVerifier returns a fixed identity for a known bearer token.
type fakeVerifier struct {
	ids map[string]authclient.Identity
}

func (f fakeVerifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if id, ok := f.ids[token]; ok {
		return id, nil
	}
	return authclient.Identity{}, ErrUnauthenticated
}

type apiFixture struct {
	s      *Server
	mem    *memstore.Mem
	hub    *stream.Hub
	enroll *enroll.Service
}

func newAPI(t *testing.T) *apiFixture {
	t.Helper()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	mem := memstore.New()
	rt := testrt.New(t, testutil.MustCA("example.org"), "lcm")
	log := rt.Logger()
	az := authz.New(mem)
	auth := ca.New(mem, env)
	aw := audit.NewWriter(mem, nil)
	t.Cleanup(aw.Close)
	issueSvc := issue.New(mem, auth, env, az, aw, nil)
	hub := stream.NewHub(stream.NewMemory(), stream.Config{ReplayWindow: time.Minute, StreamsPerUser: 5, StreamsPerTenant: 20, RetryDelay: time.Millisecond, ReadBlock: 10 * time.Millisecond}, log)
	t.Cleanup(hub.Close)
	secretsSvc := secrets.New(mem, env, aw, nil)
	webhookSvc := webhook.New(mem, env, aw, nil)
	statsSvc := stats.New(mem, hub, 24*time.Hour, nil)
	revokeSvc := revoke.New(mem, auth, nil)
	transferSvc := transfer.New(mem, env, aw, nil)
	enrollSvc := enroll.New(mem, issueSvc, az, aw, stubTokens{}, enroll.Config{AutoApprove: true}, nil)
	deploySvc := deploy.New(mem, az, env, aw, nil)

	perms := PermissionFunc(func(context.Context, string, string, string) bool { return true })
	pub := func(ctx context.Context, tenantID, eventType, certificateID, spiffeID string, notAfter time.Time) {
		payload := map[string]any{"certificate_id": certificateID, "spiffe_id": spiffeID}
		if !notAfter.IsZero() {
			payload["not_after"] = notAfter.UTC().Format(time.RFC3339)
		}
		_, _ = hub.PublishID(ctx, tenantID, nil, true, eventType, payload, false)
		if evt := map[string]string{"issued": webhook.EventIssued, "renewed": webhook.EventRenewed, "revoked": webhook.EventRevoked}[eventType]; evt != "" {
			body, _ := json.Marshal(map[string]any{"event": evt, "tenant": tenantID, "data": payload})
			_ = webhookSvc.Deliver(context.WithoutCancel(ctx), tenantID, evt, body)
		}
	}

	v := fakeVerifier{ids: map[string]authclient.Identity{
		"admin": {UserID: apiAdmin, TenantID: apiTenant, Roles: []string{"admin"}},
		"bob":   {UserID: apiBob, TenantID: apiTenant},
	}}
	s, err := NewHandler(rt, WithVerifier(v))
	if err != nil {
		t.Fatal(err)
	}
	cd := CertDeps{Issue: issueSvc, Perms: perms, Pub: pub}
	s.RegisterIssuers(cd)
	s.RegisterCertificates(cd)
	s.RegisterGrants(GrantDeps{Authz: az})
	s.RegisterEnroll(EnrollDeps{Enroll: enrollSvc, Perms: perms})
	s.RegisterDeploy(DeployDeps{Deploy: deploySvc})
	s.RegisterStream(StreamDeps{Hub: hub, Audit: aw})
	s.RegisterSecrets(SecretDeps{Secrets: secretsSvc})
	s.RegisterWebhooks(WebhookDeps{Webhooks: webhookSvc})
	s.RegisterBackup(BackupDeps{Transfer: transferSvc, MaxBytes: 1 << 20})
	s.RegisterOps(OpsDeps{Stats: statsSvc, Revoke: revokeSvc, Audit: mem, Version: "test",
		Health: func(context.Context) any { return map[string]any{"ok": true} }})
	if missing := s.Missing(); len(missing) != 0 {
		t.Fatalf("unmounted routes: %v", missing)
	}
	return &apiFixture{s: s, mem: mem, hub: hub, enroll: enrollSvc}
}

func adminSubj() authz.Subjects {
	return authz.Subjects{TenantID: apiTenant, UserID: apiAdmin, Roles: []string{"admin"}}
}

type stubTokens struct{}

func (stubTokens) VerifyEnrollment(context.Context, string) (enroll.EnrollGrant, error) {
	return enroll.EnrollGrant{}, authz.ErrForbidden
}

// req drives one request with the given token (empty => no Authorization).
func (f *apiFixture) req(t *testing.T, method, path, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}

// jsonBody decodes the JSON response body.
func jsonBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func mustStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d want %d; body=%s", w.Code, want, w.Body.String())
	}
}

// issueAndWait issues a certificate asynchronously (202) and polls the list
// until the certificate for spiffeID appears, returning its id.
func (f *apiFixture) issueAndWait(t *testing.T, body, spiffeID string) string {
	t.Helper()
	w := f.req(t, "POST", Prefix+"/certificates/issue", "admin", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("issue status = %d want 202; body=%s", w.Code, w.Body.String())
	}
	for i := 0; i < 300; i++ {
		lw := f.req(t, "GET", Prefix+"/certificates?limit=100", "admin", "")
		if lw.Code == http.StatusOK {
			var page struct {
				Items []map[string]any `json:"items"`
			}
			_ = json.Unmarshal(lw.Body.Bytes(), &page)
			for _, it := range page.Items {
				if sp, _ := it["spiffe_id"].(string); sp == spiffeID {
					if id, _ := it["id"].(string); id != "" {
						return id
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("certificate for %s never appeared (async issuance)", spiffeID)
	return ""
}

func TestIssuersAndCertificates(t *testing.T) {
	f := newAPI(t)

	// Create an issuer.
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`)
	mustStatus(t, w, http.StatusCreated)
	issuer := jsonBody(t, w)
	issuerID, _ := issuer["id"].(string)
	if issuerID == "" {
		t.Fatal("issuer id missing")
	}

	mustStatus(t, f.req(t, "GET", Prefix+"/issuers", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/issuers/"+issuerID, "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "PUT", Prefix+"/issuers/"+issuerID, "admin", `{"name":"root2","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/dns-providers", "admin", ""), http.StatusOK)

	// Issue a certificate against the default issuer (asynchronous: 202 + SSE).
	certID := f.issueAndWait(t, `{"spiffe_id":"spiffe://example.org/workload","deliver_key":true}`, "spiffe://example.org/workload")

	mustStatus(t, f.req(t, "GET", Prefix+"/certificates", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates?status=active&limit=10", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+certID, "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "PUT", Prefix+"/certificates/"+certID, "admin", `{"owner":"`+apiBob+`"}`), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/"+certID+"/download", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+certID+"/renew", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+certID+"/revoke", "admin", `{"reason":"keyCompromise"}`), http.StatusNoContent)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+certID+"/remove", "admin", ""), http.StatusNoContent)

	// The issuer still owns the (revoked) certificate, so removal is refused
	// with an in-use conflict detail.
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers/"+issuerID+"/remove", "admin", ""), http.StatusConflict)

	// A bare issuer with no certificates removes cleanly (204).
	w = f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"spare","type":"self_signed","trust_domain":"spare.example.org"}`)
	mustStatus(t, w, http.StatusCreated)
	spareID := jsonBody(t, w)["id"].(string)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers/"+spareID+"/remove", "admin", ""), http.StatusNoContent)
}

func TestGrantsAndAccess(t *testing.T) {
	f := newAPI(t)
	// An issuer to grant on.
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`)
	mustStatus(t, w, http.StatusCreated)
	issuerID := jsonBody(t, w)["id"].(string)

	// Grant bob viewer on the issuer.
	w = f.req(t, "POST", Prefix+"/grants", "admin", `{"resource_type":"issuer","resource_id":"`+issuerID+`","subject_type":"user","subject_id":"`+apiBob+`","relation":"viewer"}`)
	mustStatus(t, w, http.StatusCreated)
	grantID := jsonBody(t, w)["id"].(string)

	mustStatus(t, f.req(t, "GET", Prefix+"/grants?resource_type=issuer&resource_id="+issuerID, "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/access/check?resource_type=issuer&resource_id="+issuerID+"&action=read", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/access/effective?resource_type=issuer&resource_id="+issuerID, "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/access/accessible?resource_type=issuer", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/grants/"+grantID+"/revoke", "admin", ""), http.StatusNoContent)

	// Bob (viewer removed) is forbidden -> masked to 404 on effective read.
	mustStatus(t, f.req(t, "GET", Prefix+"/access/check?resource_type=issuer&resource_id="+issuerID+"&action=read", "bob", ""), http.StatusOK)
}

func TestEnrollRequestsJobs(t *testing.T) {
	f := newAPI(t)
	// Default issuer for auto-approve issuance.
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)

	// /enroll is a public, enrollment-token-authenticated route. The test
	// verifier rejects tokens, so a bogus token is forbidden; inline auto-approve
	// issuance is covered by the enroll service tests (fake verifier).
	w := f.req(t, "POST", Prefix+"/enroll", "admin", `{"spiffe_id":"spiffe://example.org/agent","enrollment_token":"bogus"}`)
	mustStatus(t, w, http.StatusForbidden)

	mustStatus(t, f.req(t, "GET", Prefix+"/requests", "admin", ""), http.StatusOK)

	// POST /requests creates a pending certificate request (the handler accepts
	// the shared IssueInput schema, ignoring deliver_key for a request).
	mustStatus(t, f.req(t, "POST", Prefix+"/requests", "admin", `{"spiffe_id":"spiffe://example.org/svc-a"}`), http.StatusCreated)

	// Seed a pending request through the service, then drive get/approve.
	rv, err := f.enroll.CreateRequest(context.Background(), adminSubj(), enroll.RequestInput{SpiffeID: "spiffe://example.org/svc-a"})
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	mustStatus(t, f.req(t, "GET", Prefix+"/requests/"+rv.ID, "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/requests/"+rv.ID+"/approve", "admin", `{"reason":"ok"}`), http.StatusOK)

	// A second request to reject.
	rv2, err := f.enroll.CreateRequest(context.Background(), adminSubj(), enroll.RequestInput{SpiffeID: "spiffe://example.org/svc-b"})
	if err != nil {
		t.Fatalf("seed request 2: %v", err)
	}
	mustStatus(t, f.req(t, "POST", Prefix+"/requests/"+rv2.ID+"/reject", "admin", `{"reason":"no"}`), http.StatusOK)

	mustStatus(t, f.req(t, "GET", Prefix+"/jobs", "admin", ""), http.StatusOK)
	// Unknown job is masked as not found.
	mustStatus(t, f.req(t, "GET", Prefix+"/jobs/"+apiBob, "admin", ""), http.StatusNotFound)
}

func TestDeploySecretsWebhooks(t *testing.T) {
	f := newAPI(t)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)
	certID := f.issueAndWait(t, `{"spiffe_id":"spiffe://example.org/deployme","deliver_key":true}`, "spiffe://example.org/deployme")

	mustStatus(t, f.req(t, "GET", Prefix+"/installed", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/deployment-targets", "admin", ""), http.StatusOK)
	w := f.req(t, "POST", Prefix+"/deployment-targets", "admin", `{"name":"host-a","kind":"file","config":{"path":"/etc/certs"}}`)
	mustStatus(t, w, http.StatusCreated)
	targetID := jsonBody(t, w)["id"].(string)
	mustStatus(t, f.req(t, "POST", Prefix+"/certificates/"+certID+"/deploy", "admin", `{"target_id":"`+targetID+`"}`), http.StatusOK)

	// Secrets.
	mustStatus(t, f.req(t, "GET", Prefix+"/secrets", "admin", ""), http.StatusOK)
	w = f.req(t, "POST", Prefix+"/secrets", "admin", `{"name":"acct","kind":"acme_account","value":{"account_key":"pem"}}`)
	mustStatus(t, w, http.StatusCreated)
	secID := jsonBody(t, w)["id"].(string)
	mustStatus(t, f.req(t, "PUT", Prefix+"/secrets/"+secID, "admin", `{"name":"acct2","kind":"acme_account","value":{"account_key":"pem2"}}`), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/secrets/"+secID+"/rotate", "admin", `{"value":{"account_key":"pem3"}}`), http.StatusOK)
	mustStatus(t, f.req(t, "POST", Prefix+"/secrets/"+secID+"/remove", "admin", ""), http.StatusNoContent)

	// Webhooks.
	mustStatus(t, f.req(t, "GET", Prefix+"/webhooks", "admin", ""), http.StatusOK)
	w = f.req(t, "POST", Prefix+"/webhooks", "admin", `{"name":"hook","url":"https://example.com/hook","event_types":["certificate.issued"],"secret":"s3cr3t-value-abcdefabcdef"}`)
	mustStatus(t, w, http.StatusCreated)
	hookID := jsonBody(t, w)["id"].(string)
	mustStatus(t, f.req(t, "POST", Prefix+"/webhooks/"+hookID+"/remove", "admin", ""), http.StatusNoContent)
}

func TestOpsRoutes(t *testing.T) {
	f := newAPI(t)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)

	mustStatus(t, f.req(t, "GET", Prefix+"/stats", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/audit?limit=10", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/audit?event_type=x&actor_id=y&from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/trust-bundle?trust_domain=example.org", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/revocations", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/crl?trust_domain=example.org", "admin", ""), http.StatusOK)
	mustStatus(t, f.req(t, "GET", Prefix+"/health", "admin", ""), http.StatusOK)
}

func TestBackupExportImport(t *testing.T) {
	f := newAPI(t)
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"root","type":"self_signed","trust_domain":"example.org","is_default":true}`), http.StatusCreated)

	w := f.req(t, "POST", Prefix+"/backup/export", "admin", `{"include_credentials":false}`)
	mustStatus(t, w, http.StatusOK)
	doc := w.Body.String()

	// Round-trip the exported document back in (skip mode).
	mustStatus(t, f.req(t, "POST", Prefix+"/backup/import?mode=skip", "admin", doc), http.StatusOK)
}

func TestBackupImportOversize(t *testing.T) {
	f := newAPI(t)
	// Body larger than the configured 1 MiB import limit -> 413.
	big := strings.Repeat("a", (1<<20)+1024)
	w := f.req(t, "POST", Prefix+"/backup/import", "admin", `{"x":"`+big+`"}`)
	mustStatus(t, w, http.StatusRequestEntityTooLarge)
}

func TestRefusalPaths(t *testing.T) {
	f := newAPI(t)

	// 401 without a token.
	mustStatus(t, f.req(t, "GET", Prefix+"/stats", "", ""), http.StatusUnauthorized)
	// 401 with an unknown token.
	mustStatus(t, f.req(t, "GET", Prefix+"/stats", "nope", ""), http.StatusUnauthorized)

	// 404 masking: a well-formed but unknown certificate id.
	mustStatus(t, f.req(t, "GET", Prefix+"/certificates/44444444-4444-7444-8444-444444444444", "admin", ""), http.StatusNotFound)

	// 422 validation: issuer body missing required fields.
	mustStatus(t, f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"x"}`), http.StatusUnprocessableEntity)

	// 400 malformed JSON that still matches the content type.
	w := f.req(t, "POST", Prefix+"/issuers", "admin", `{"name":"x","type":"self_signed","trust_domain":"example.org"`)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed body status = %d", w.Code)
	}

	// Unknown route under the API prefix -> 404.
	mustStatus(t, f.req(t, "GET", Prefix+"/nope", "admin", ""), http.StatusNotFound)
}

func TestStreamRoute(t *testing.T) {
	f := newAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "https://localhost"+Prefix+"/stream", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer admin")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { f.s.Handler().ServeHTTP(w, r); close(done) }()
	// Publish an event, then let the stream flush and cancel.
	time.Sleep(20 * time.Millisecond)
	_, _ = f.hub.PublishID(context.Background(), apiTenant, nil, true, "issued", map[string]any{"certificate_id": "c1"}, false)
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not close")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("stream status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "event:") && !strings.Contains(w.Body.String(), "data:") {
		t.Logf("stream body: %q", w.Body.String())
	}
}
