package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

func newBare(t *testing.T, opts ...Option) *Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "lcm")
	s, err := NewHandler(rt, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRemoteServing(t *testing.T) {
	s := newBare(t, WithRemote(fstest.MapFS{
		"mf-manifest.json": {Data: []byte(`{"id":"lcm"}`)},
		"assets/a.js":      {Data: []byte("1")},
		"dir/index.html":   {Data: []byte("x")},
	}))
	get := func(p string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://localhost"+p, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := get("/ui/mf-manifest.json"); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest: %d %s", w.Code, w.Header())
	}
	if w := get("/ui/assets/a.js"); w.Code != 200 || w.Header().Get("Cache-Control") == "" {
		t.Fatalf("asset: %d", w.Code)
	}
	for _, p := range []string{"/ui/", "/ui/dir/", "/ui/missing.js"} {
		if w := get(p); w.Code != 404 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

func TestServerRouteBookkeeping(t *testing.T) {
	s := newBare(t)
	if len(s.Declared()) == 0 {
		t.Fatal("no declared routes")
	}
	if len(s.Missing()) != len(s.Declared()) {
		t.Fatal("nothing should be implemented yet")
	}
	if len(s.Implemented()) != 0 {
		t.Fatal("implemented should be empty")
	}
	if s.Document() == nil {
		t.Fatal("nil document")
	}
	if s.Edge() != nil {
		t.Fatal("NewHandler has no edge listener")
	}

	// Mount one real route and confirm bookkeeping updates.
	d := s.Declared()[0]
	if err := s.HandleFunc(d.Method, d.Path, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(s.Implemented()) != 1 || len(s.Missing()) != len(s.Declared())-1 {
		t.Fatal("bookkeeping not updated")
	}

	// Undeclared route is refused.
	if err := s.HandleFunc("GET", "/not/declared", func(http.ResponseWriter, *http.Request) {}); err == nil {
		t.Fatal("undeclared route accepted")
	}

	// MustHandle panics on an undeclared route.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MustHandle should panic")
			}
		}()
		s.MustHandle("GET", "/still/not/declared", func(http.ResponseWriter, *http.Request) {})
	}()

	// A GET with no token is refused (401) before reaching an unimplemented
	// handler; the trust-bundle route needs only a query param, so validation
	// passes and authentication is what refuses it.
	r := httptest.NewRequest("GET", "https://localhost"+Prefix+"/trust-bundle?trust_domain=example.org", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no verifier => 401, got %d", w.Code)
	}
}

func TestHasPermission(t *testing.T) {
	called := false
	pc := PermissionFunc(func(_ context.Context, tid, uid, perm string) bool {
		called = true
		return tid == apiTenant && uid == apiAdmin && perm == "stats:read"
	})
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(authclient.WithIdentity(r.Context(), authclient.Identity{TenantID: apiTenant, UserID: apiAdmin}))
	if !hasPermission(r, pc, "stats:read") || !called {
		t.Fatal("permission should be granted")
	}
	if hasPermission(r, pc, "other") {
		t.Fatal("wrong permission granted")
	}
}
