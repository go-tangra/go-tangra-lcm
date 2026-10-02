package app

import (
	"context"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1" // registers lcm.v1
	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/identity"
)

// lcmOps lists every lcm.v1 RPC as a policy operation.
func lcmOps(t *testing.T) []string {
	t.Helper()
	fd, err := protoregistry.GlobalFiles.FindFileByPath("lcm/v1/lcm.proto")
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	svcs := fd.Services()
	for i := 0; i < svcs.Len(); i++ {
		s := svcs.Get(i)
		ms := s.Methods()
		for j := 0; j < ms.Len(); j++ {
			ops = append(ops, "/"+string(s.FullName())+"/"+string(ms.Get(j).Name()))
		}
	}
	return ops
}

func loadPolicy(t *testing.T) *authz.Policy {
	t.Helper()
	f, err := os.Open("../../deploy/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	pol, err := authz.Load(f)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return pol
}

// The inventory-download rule (inventory feature 033) admits svc/inventory
// to Certificates/Download only: inventory relays a certificate to its agent
// at fetch time. Enrollment stays open to every workload (workloads-renew);
// nothing else in lcm is granted to inventory.
func TestPolicyInventoryDownload(t *testing.T) {
	pol := loadPolicy(t)
	inv := identity.ForService("example.org", "inventory")
	allowed := map[string]string{
		"/lcm.v1.Certificates/Download": "inventory-download",
		"/lcm.v1.Enrollment/Enroll":     "workloads-renew",
	}
	ops := append(lcmOps(t), "/grpc.health.v1.Health/Check", "/scheduler.v1.TaskExecutor/ExecuteTask")
	seen := 0
	for _, op := range ops {
		d := pol.Authorize(context.Background(), inv, "lcm", op)
		rule, want := allowed[op]
		if d.Allowed != want {
			t.Errorf("inventory %s: allowed=%v (rule %q)", op, d.Allowed, d.RuleID)
		}
		if d.Allowed {
			seen++
			if d.RuleID != rule {
				t.Errorf("inventory %s allowed by %q, want %q", op, d.RuleID, rule)
			}
		}
	}
	if seen != len(allowed) {
		t.Fatalf("inventory allowed %d operations, want %d", seen, len(allowed))
	}
	// Download stays limited to the deployer and inventory.
	for svc, want := range map[string]bool{"deployer": true, "inventory": true, "asset": false, "ipam": false, "scheduler": false} {
		if got := pol.Authorize(context.Background(), identity.ForService("example.org", svc), "lcm", "/lcm.v1.Certificates/Download").Allowed; got != want {
			t.Errorf("%s Download allowed=%v, want %v", svc, got, want)
		}
	}
}
