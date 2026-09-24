package contract

import (
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/pkg/lcmmanifest"
)

// TestManifestMatchesContract builds the manifest from the OpenAPI document
// and checks it against contracts/manifest.md.
func TestManifestMatchesContract(t *testing.T) {
	m, err := lcmmanifest.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Module != "lcm" || m.Version != "1.0.0" || len(m.Prefixes) != 1 || len(m.Permissions) != 14 || len(m.Abilities) != 9 || len(m.Nav) != 7 || len(m.Methods) != 0 || len(m.Exposes) != 3 {
		t.Fatalf("%+v", m)
	}
	if m.Prefixes[0] != "/api/lcm" {
		t.Fatalf("prefix %q", m.Prefixes[0])
	}
	byKey := map[string]int{}
	for i, r := range m.Routes {
		byKey[r.Method+" "+r.Path] = i
	}
	check := func(key, perm string, public bool, body uint64, timeout time.Duration) {
		t.Helper()
		i, ok := byKey[key]
		if !ok {
			t.Fatalf("%s missing", key)
		}
		r := m.Routes[i]
		if r.Permission != perm || r.Public != public || r.MaxBodyBytes != body || r.Timeout != timeout || r.ClientAddress {
			t.Errorf("%s: %+v", key, r)
		}
	}
	check("POST /api/lcm/v1/certificates/issue", "certificates:issue", false, 0, 60*time.Second)
	check("POST /api/lcm/v1/certificates/{id}/revoke", "certificates:revoke", false, 0, 0)
	check("GET /api/lcm/v1/certificates/{id}", "certificates:read", false, 0, 0)
	check("POST /api/lcm/v1/issuers", "issuers:manage", false, 0, 0)
	check("GET /api/lcm/v1/issuers", "issuers:read", false, 0, 0)
	check("POST /api/lcm/v1/enroll", "", true, 0, 60*time.Second)
	check("GET /api/lcm/v1/bootstrap-bundle", "", true, 0, 0)
	check("GET /api/lcm/v1/stream", "certificates:read", false, 0, 300*time.Second)
	check("POST /api/lcm/v1/backup/import", "backup:manage", false, 16777216, 120*time.Second)
	check("POST /api/lcm/v1/grants", "permissions:manage", false, 0, 0)
	// The only public routes are the cold-start enrollment + bootstrap-bundle
	// endpoints (a workload has no platform token yet); the remote is /m/lcm/.
	publicRoutes := map[string]bool{}
	for _, r := range m.Routes {
		if r.Public {
			publicRoutes[r.Method+" "+r.Path] = true
		}
	}
	for _, want := range []string{"POST /api/lcm/v1/enroll", "GET /api/lcm/v1/bootstrap-bundle"} {
		if !publicRoutes[want] {
			t.Errorf("expected public route %s", want)
		}
		delete(publicRoutes, want)
	}
	for k := range publicRoutes {
		t.Errorf("unexpected public route %s", k)
	}
	perms := map[string]bool{}
	for _, p := range lcmmanifest.PermissionRefs() {
		perms[p] = true
	}
	for _, a := range m.Abilities {
		if !perms[a.Requires] {
			t.Errorf("ability requires %q", a.Requires)
		}
	}
	for _, n := range m.Nav {
		if !perms[n.Requires] {
			t.Errorf("nav requires %q", n.Requires)
		}
	}
	for role, refs := range lcmmanifest.Grants {
		for _, ref := range refs {
			if !perms[ref] {
				t.Errorf("grant %s -> %q", role, ref)
			}
		}
	}
}
