package deploy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
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
	return New(st, authz.New(st), env, aw, func() time.Time { return time.Unix(1700000000, 0) }), st
}

func admin() authz.Subjects {
	return authz.Subjects{TenantID: tenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

func seedCert(t *testing.T, st *memstore.Mem) string {
	t.Helper()
	// an issuer is needed for the FK; insert a minimal issuer + certificate.
	iss := store.Issuer{ID: store.NewID(), TenantID: tenant, Name: "i", Type: "self_signed", TrustDomain: "example.org", Enabled: true}
	if err := st.InsertIssuer(context.Background(), iss); err != nil {
		t.Fatal(err)
	}
	c := store.IssuedCertificate{ID: store.NewID(), TenantID: tenant, IssuerID: iss.ID, Serial: "01", SpiffeID: "spiffe://example.org/svc/a", Status: "active", CertPEM: "x", NotBefore: time.Unix(1, 0), NotAfter: time.Unix(1<<31, 0)}
	if err := st.InsertCertificate(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

func TestTargets_CreateListRedactsSecret(t *testing.T) {
	ctx := context.Background()
	s, _ := newSvc(t)
	tv, err := s.CreateTarget(ctx, admin(), TargetInput{Name: "prod", Kind: "webhook", Config: sealed.Settings{"url": "https://x", "token": "SECRET"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tv.Config["token"] != sealed.Marker {
		t.Fatalf("token must be redacted, got %v", tv.Config["token"])
	}
	if tv.Config["url"] != "https://x" {
		t.Fatalf("url lost: %v", tv.Config["url"])
	}
	list, err := s.ListTargets(ctx, admin())
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v n=%d", err, len(list))
	}
	if list[0].Config["token"] != sealed.Marker {
		t.Fatal("listed token not redacted")
	}
	// bad kind rejected
	if _, err := s.CreateTarget(ctx, admin(), TargetInput{Name: "x", Kind: "bogus"}); err == nil {
		t.Fatal("bad kind accepted")
	}
}

func TestInstalledAndDeploy(t *testing.T) {
	ctx := context.Background()
	s, st := newSvc(t)
	certID := seedCert(t, st)
	if err := s.ReportInstalled(ctx, admin(), certID, "spiffe://example.org/agent/1"); err != nil {
		t.Fatalf("report: %v", err)
	}
	items, err := s.ListInstalled(ctx, admin(), "", time.Unix(1800000000, 0), 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("installed: %v n=%d", err, len(items))
	}
	tv, err := s.CreateTarget(ctx, admin(), TargetInput{Name: "t", Kind: "pull"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deploy(ctx, admin(), certID, tv.ID); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// missing certificate/client rejected
	if err := s.ReportInstalled(ctx, admin(), "", ""); err == nil {
		t.Fatal("empty ids accepted")
	}
	_ = errors.Is
}
