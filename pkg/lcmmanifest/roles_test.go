package lcmmanifest_test

import (
	"slices"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/pkg/lcmmanifest"
)

// TestRoles checks the module role set (feature 019, research D9): slugs,
// display names and permissions, all of them the module's own.
func TestRoles(t *testing.T) {
	want := map[string]struct {
		name  string
		perms []string
	}{
		"administrator": {"Certificates administrator", lcmmanifest.PermissionRefs()},
		"operator":      {"Certificates operator", []string{"certificates:read", "certificates:issue", "certificates:manage", "certificates:revoke", "issuers:read", "jobs:read", "jobs:manage", "enrollment:enroll"}},
		"viewer":        {"Certificates viewer", []string{"certificates:read", "issuers:read", "jobs:read"}},
	}
	own := map[string]bool{}
	for _, p := range lcmmanifest.PermissionRefs() {
		own[p] = true
	}
	if len(lcmmanifest.Roles) != len(want) {
		t.Fatalf("%d roles, want %d", len(lcmmanifest.Roles), len(want))
	}
	for _, r := range lcmmanifest.Roles {
		w, ok := want[r.Slug]
		if !ok {
			t.Fatalf("unexpected role %q", r.Slug)
		}
		if r.DisplayName != w.name || r.Description == "" {
			t.Errorf("%s: name %q, description %q", r.Slug, r.DisplayName, r.Description)
		}
		if !slices.Equal(r.Permissions, w.perms) {
			t.Errorf("%s: %v, want %v", r.Slug, r.Permissions, w.perms)
		}
		for _, p := range r.Permissions {
			if !own[p] {
				t.Errorf("%s names %q, not an lcm permission", r.Slug, p)
			}
		}
	}
}

// TestRegistration checks the registration sent to auth: module identity,
// every permission, the role set and the built-in grants; auth's rules hold.
func TestRegistration(t *testing.T) {
	reg := lcmmanifest.Registration()
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	if reg.Module != "lcm" || reg.DisplayName != "Certificates" || len(reg.Permissions) != len(lcmmanifest.Permissions) || len(reg.Roles) != 3 {
		t.Fatalf("%+v", reg)
	}
	for i, p := range lcmmanifest.Permissions {
		if got := reg.Permissions[i]; got.Resource != p.Resource || got.Action != p.Action || got.Description != p.Description {
			t.Errorf("permission %d: %+v", i, got)
		}
	}
	for _, slug := range []string{"owner", "admin", "member", "auditor", "operator"} {
		if !slices.Equal(reg.BuiltinGrants[slug], lcmmanifest.Grants[slug]) {
			t.Errorf("grant %s: %v", slug, reg.BuiltinGrants[slug])
		}
	}
}

// Before feature 019 the auditor held the unscoped jobs:read of every module;
// it keeps reading lcm jobs after prune-legacy.
func TestAuditorReadsJobs(t *testing.T) {
	want := []string{"stats:read", "certificates:read", "jobs:read"}
	if !slices.Equal(lcmmanifest.Grants["auditor"], want) {
		t.Fatalf("auditor grants: %v", lcmmanifest.Grants["auditor"])
	}
}
