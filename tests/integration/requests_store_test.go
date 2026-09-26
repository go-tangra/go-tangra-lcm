//go:build integration

// ACME orders are recorded as generic certificate requests: the migrations
// (through 0008) run against a real TimescaleDB, a generic request with no
// SPIFFE id round-trips, the processing/failed statuses are accepted and
// CompleteRequest links the issued certificate or records the failure reason.
//
// Run: go test -tags integration -run RequestsStore ./tests/integration/
// (needs Docker; skips cleanly without it).
package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const timescaleImage = "timescale/timescaledb:latest-pg16"

func startTimescale(t *testing.T, ctx context.Context) string {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{Started: true, ContainerRequest: testcontainers.ContainerRequest{
		Image: timescaleImage, ExposedPorts: []string{"5432/tcp"},
		Env:        map[string]string{"POSTGRES_PASSWORD": "lcm", "POSTGRES_USER": "lcm", "POSTGRES_DB": "lcm"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90 * time.Second),
	}})
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("postgres://lcm:lcm@%s:%s/lcm?sslmode=disable", host, port.Port())
}

func TestRequestsStore_GenericACMERequests(t *testing.T) {
	ctx := context.Background()
	dsn := startTimescale(t, ctx)
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Open(ctx, dsn, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := repodb.New(st)

	issuerID := store.NewID()
	if err := db.InsertIssuer(ctx, store.Issuer{ID: issuerID, TenantID: tenant, Name: "le", Type: "acme", TrustDomain: "example.org", Enabled: true}); err != nil {
		t.Fatalf("issuer: %v", err)
	}

	// A generic (ACME) request: no SPIFFE id, domains as SANs, status processing.
	gen := store.CertificateRequest{
		ID: store.NewID(), TenantID: tenant, IssuerID: &issuerID, Kind: "generic",
		SANs: []byte(`["example.org","*.example.org"]`), RequestedBy: "u1", RequesterKind: "user", Status: "processing",
	}
	if err := db.InsertRequest(ctx, gen); err != nil {
		t.Fatalf("insert generic: %v", err)
	}
	got, err := db.GetRequest(ctx, tenant, gen.ID)
	if err != nil {
		t.Fatalf("get generic: %v", err)
	}
	if got.Kind != "generic" || got.SpiffeID != "" || got.Status != "processing" || got.CertificateID != nil {
		t.Fatalf("generic row = %+v", got)
	}

	// An svid request keeps the default kind.
	svid := store.CertificateRequest{
		ID: store.NewID(), TenantID: tenant, SpiffeID: "spiffe://example.org/w", RequestedBy: "u1", RequesterKind: "user", Status: "pending",
	}
	if err := db.InsertRequest(ctx, svid); err != nil {
		t.Fatalf("insert svid: %v", err)
	}
	if g, err := db.GetRequest(ctx, tenant, svid.ID); err != nil || g.Kind != "svid" || g.SpiffeID != "spiffe://example.org/w" {
		t.Fatalf("svid row = %+v, %v", g, err)
	}

	// processing is a listable status.
	rows, err := db.ListRequests(ctx, tenant, store.RequestFilter{Status: "processing", Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != gen.ID {
		t.Fatalf("list processing = %+v, %v", rows, err)
	}

	// Completing as issued links the certificate.
	certID := store.NewID()
	if err := db.CompleteRequest(ctx, tenant, gen.ID, "issued", &certID, nil); err != nil {
		t.Fatalf("complete issued: %v", err)
	}
	got, _ = db.GetRequest(ctx, tenant, gen.ID)
	if got.Status != "issued" || got.CertificateID == nil || *got.CertificateID != certID {
		t.Fatalf("issued row = %+v", got)
	}

	// A second order fails with a reason.
	failed := gen
	failed.ID = store.NewID()
	if err := db.InsertRequest(ctx, failed); err != nil {
		t.Fatal(err)
	}
	reason := "acme: order failed: bad domain"
	if err := db.CompleteRequest(ctx, tenant, failed.ID, "failed", nil, &reason); err != nil {
		t.Fatalf("complete failed: %v", err)
	}
	got, _ = db.GetRequest(ctx, tenant, failed.ID)
	if got.Status != "failed" || got.Reason == nil || *got.Reason != reason || got.CertificateID != nil {
		t.Fatalf("failed row = %+v", got)
	}
	if rows, err := db.ListRequests(ctx, tenant, store.RequestFilter{Status: "failed", Limit: 10}); err != nil || len(rows) != 1 {
		t.Fatalf("list failed = %+v, %v", rows, err)
	}

	// Unknown request and a status outside the CHECK are refused.
	if err := db.CompleteRequest(ctx, tenant, store.NewID(), "issued", &certID, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("complete unknown: %v", err)
	}
	if err := db.CompleteRequest(ctx, tenant, gen.ID, "bogus", nil, nil); err == nil {
		t.Fatal("status outside the CHECK constraint accepted")
	}
}
