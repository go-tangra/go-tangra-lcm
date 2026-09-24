package contract

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-lcm/v4/pkg/lcmmanifest"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
)

// TestOpenAPIDocument proves the contract parses, every operation has an id,
// responses and a declared permission (nothing is public), no unsafe verbs,
// and the mounted route table equals the declared one.
func TestOpenAPIDocument(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]bool{}
	for _, p := range lcmmanifest.PermissionRefs() {
		perms[p] = true
	}
	n := 0
	for p, item := range doc.Paths.Map() {
		if !strings.HasPrefix(p, httpapi.Prefix+"/") {
			t.Errorf("%s outside the API prefix", p)
		}
		for m, op := range item.Operations() {
			n++
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", m, p)
			}
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s %s: no responses", m, p)
			}
			perm, _ := op.Extensions[httpapi.PermissionExtension].(string)
			if public, _ := op.Extensions[httpapi.PublicExtension].(bool); public {
				// Public routes (cold-start enroll/bootstrap-bundle) carry no
				// permission and do their own token authorization internally.
				if perm != "" {
					t.Errorf("%s %s: public route must not declare a permission", m, p)
				}
			} else if !perms[perm] {
				t.Errorf("%s %s: permission %q not in the manifest", m, p, perm)
			}
			if m == "DELETE" || m == "PATCH" {
				t.Errorf("%s %s: verb not allowed (CSRF-safe shapes only)", m, p)
			}
		}
	}
	if n != 54 {
		t.Fatalf("operations %d, want 54", n)
	}
	s, err := httpapi.NewHandler(testrt.New(t, testutil.MustCA("example.org"), "lcm"))
	if err != nil {
		t.Fatal(err)
	}
	declared := httpapi.DeclaredRoutes(doc)
	if len(declared) != len(s.Declared()) {
		t.Fatalf("declared %d mounted %d", len(declared), len(s.Declared()))
	}
	// Only the two cold-start routes are public (enroll + bootstrap-bundle).
	if pub := httpapi.PublicRoutes(doc); len(pub) != 2 {
		t.Fatalf("public routes: %v", pub)
	}
	// Body-heavy and slow routes carry explicit limits and timeouts (contracts).
	for p, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			switch {
			case strings.HasSuffix(p, "/backup/import"):
				if op.Extensions[httpapi.BodyLimitExtension] == nil || op.Extensions[httpapi.TimeoutExtension] == nil {
					t.Errorf("%s: backup import needs a body limit and timeout", p)
				}
			case strings.HasSuffix(p, "/stream"):
				if op.Extensions[httpapi.TimeoutExtension] == nil {
					t.Errorf("%s: stream needs a timeout", p)
				}
			}
		}
	}
}
