package lcmclient

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	lcmv1 "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeSVID implements the couple of SVID methods the tests exercise.
type fakeSVID struct {
	lcmv1.UnimplementedSVIDServer
	lastRenew  *lcmv1.RenewRequest
	lastVerify *lcmv1.VerifyRequest
	notAfter   time.Time
}

func (f *fakeSVID) Renew(_ context.Context, in *lcmv1.RenewRequest) (*lcmv1.CertificateBundle, error) {
	f.lastRenew = in
	return &lcmv1.CertificateBundle{
		CertPem:   "RENEWED-CERT",
		ChainPem:  "CHAIN",
		BundlePem: "ROOTS",
		KeyPem:    "RENEWED-KEY",
		Certificate: &lcmv1.Certificate{
			Serial:   "serial-2",
			SpiffeId: "spiffe://td/wl",
			NotAfter: timestamppb.New(f.notAfter),
		},
	}, nil
}

func (f *fakeSVID) Verify(_ context.Context, in *lcmv1.VerifyRequest) (*lcmv1.VerifyResponse, error) {
	f.lastVerify = in
	return &lcmv1.VerifyResponse{Valid: in.GetSerial() == "good-serial", Reason: "ok"}, nil
}

// fakeEnroll implements Enrollment.Enroll.
type fakeEnroll struct {
	lcmv1.UnimplementedEnrollmentServer
	last     *lcmv1.EnrollRequest
	notAfter time.Time
}

func (f *fakeEnroll) Enroll(_ context.Context, in *lcmv1.EnrollRequest) (*lcmv1.CertificateBundle, error) {
	f.last = in
	return &lcmv1.CertificateBundle{
		CertPem:   "CERT",
		ChainPem:  "CHAIN",
		BundlePem: "ROOTS",
		KeyPem:    "KEY",
		Certificate: &lcmv1.Certificate{
			Serial:   "serial-1",
			SpiffeId: in.GetSpiffeId(),
			NotAfter: timestamppb.New(f.notAfter),
		},
	}, nil
}

// fakeAgent streams a fixed set of updates.
type fakeAgent struct {
	lcmv1.UnimplementedAgentServer
	updates []*lcmv1.CertificateUpdate
	lastReq *lcmv1.WatchRequest
}

func (f *fakeAgent) Watch(in *lcmv1.WatchRequest, stream grpc.ServerStreamingServer[lcmv1.CertificateUpdate]) error {
	f.lastReq = in
	for _, u := range f.updates {
		if err := stream.Send(u); err != nil {
			return err
		}
	}
	return nil // clean end of stream
}

// newTestClient spins up an in-process gRPC server with the given fakes and
// returns a Client wired to it plus a cleanup func.
func newTestClient(t *testing.T, svid lcmv1.SVIDServer, enroll lcmv1.EnrollmentServer, agent lcmv1.AgentServer) (*Client, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	if svid != nil {
		lcmv1.RegisterSVIDServer(srv, svid)
	}
	if enroll != nil {
		lcmv1.RegisterEnrollmentServer(srv, enroll)
	}
	if agent != nil {
		lcmv1.RegisterAgentServer(srv, agent)
	}
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
	return New(conn), cleanup
}

func TestEnroll(t *testing.T) {
	na := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	fe := &fakeEnroll{notAfter: na}
	c, cleanup := newTestClient(t, nil, fe, nil)
	defer cleanup()

	b, err := c.Enroll(context.Background(), EnrollRequest{
		TenantID:        "tenant-1",
		SpiffeID:        "spiffe://td/wl",
		EnrollmentToken: "tok",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if fe.last.GetTenantId() != "tenant-1" || fe.last.GetSpiffeId() != "spiffe://td/wl" || fe.last.GetEnrollmentToken() != "tok" {
		t.Fatalf("request not mapped: %+v", fe.last)
	}
	if b.CertPEM != "CERT" || b.KeyPEM != "KEY" || b.BundlePEM != "ROOTS" || b.ChainPEM != "CHAIN" {
		t.Fatalf("bundle PEM not mapped: %+v", b)
	}
	if b.Serial != "serial-1" || b.SpiffeID != "spiffe://td/wl" {
		t.Fatalf("bundle cert fields not mapped: %+v", b)
	}
	if !b.NotAfter.Equal(na) {
		t.Fatalf("NotAfter = %v, want %v", b.NotAfter, na)
	}
}

func TestRenew(t *testing.T) {
	na := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	fs := &fakeSVID{notAfter: na}
	c, cleanup := newTestClient(t, fs, nil, nil)
	defer cleanup()

	b, err := c.RenewTenant(context.Background(), "tenant-1", "cert-abc")
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if fs.lastRenew.GetCertificateId() != "cert-abc" || fs.lastRenew.GetTenantId() != "tenant-1" {
		t.Fatalf("renew request not mapped: %+v", fs.lastRenew)
	}
	if b.CertPEM != "RENEWED-CERT" || b.Serial != "serial-2" || !b.NotAfter.Equal(na) {
		t.Fatalf("renewed bundle not mapped: %+v", b)
	}
}

func TestVerify(t *testing.T) {
	fs := &fakeSVID{}
	c, cleanup := newTestClient(t, fs, nil, nil)
	defer cleanup()

	ok, err := c.Verify(context.Background(), "good-serial")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("Verify(good-serial) = false, want true")
	}
	if fs.lastVerify.GetSerial() != "good-serial" {
		t.Fatalf("verify serial not mapped: %+v", fs.lastVerify)
	}

	bad, err := c.Verify(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if bad {
		t.Fatalf("Verify(nope) = true, want false")
	}
}

func TestWatch(t *testing.T) {
	na := time.Now().Add(time.Hour).Truncate(time.Second)
	fa := &fakeAgent{updates: []*lcmv1.CertificateUpdate{
		{Type: "issued", CertificateId: "c1", SpiffeId: "spiffe://td/wl", NotAfter: timestamppb.New(na)},
		{Type: "renewed", CertificateId: "c2", SpiffeId: "spiffe://td/wl"},
		{Type: "revoked", CertificateId: "c3", SpiffeId: "spiffe://td/wl"},
	}}
	c, cleanup := newTestClient(t, nil, nil, fa)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var got []Update
	err := c.WatchTenant(ctx, "tenant-1", "evt-0", func(u Update) {
		got = append(got, u)
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if fa.lastReq.GetTenantId() != "tenant-1" || fa.lastReq.GetLastEventId() != "evt-0" {
		t.Fatalf("watch request not mapped: %+v", fa.lastReq)
	}
	if len(got) != 3 {
		t.Fatalf("got %d updates, want 3: %+v", len(got), got)
	}
	if got[0].Type != "issued" || got[0].CertificateID != "c1" || got[0].SpiffeID != "spiffe://td/wl" {
		t.Fatalf("update[0] not mapped: %+v", got[0])
	}
	if !got[0].NotAfter.Equal(na) {
		t.Fatalf("update[0].NotAfter = %v, want %v", got[0].NotAfter, na)
	}
	if got[1].Type != "renewed" || got[2].Type != "revoked" {
		t.Fatalf("update types not mapped: %+v", got)
	}
}

func TestMaterializeAtomic(t *testing.T) {
	dir := t.TempDir()
	cfg := AgentConfig{WriteDir: dir}
	b := &Bundle{CertPEM: "C", ChainPEM: "H", BundlePEM: "R", KeyPEM: "K"}
	if err := cfg.materialize(b); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	assertFile(t, dir, certFile, "C", 0o644)
	assertFile(t, dir, keyFile, "K", 0o600)
	assertFile(t, dir, bundleFile, "R", 0o644)
	assertFile(t, dir, chainFile, "H", 0o644)
}

func assertFile(t *testing.T, dir, name, want string, mode uint32) {
	t.Helper()
	path := filepath.Join(dir, name)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if uint32(fi.Mode().Perm()) != mode {
		t.Fatalf("%s mode = %o, want %o", name, fi.Mode().Perm(), mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", name, data, want)
	}
}
