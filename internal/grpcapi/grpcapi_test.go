package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lcmv1 "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/stream"
)

const (
	gTenant  = "11111111-1111-7111-8111-111111111111"
	gSpiffe  = "spiffe://example.org/svc/agent-1"
	gTrustTD = "example.org"
)

type gfixture struct {
	svid   *SVIDServer
	enroll *EnrollmentServer
	events *EventsServer
	agent  *AgentServer
	az     *authz.Authorizer
	mem    *memstore.Mem
	hub    *stream.Hub
}

func newGRPC(t *testing.T) *gfixture {
	t.Helper()
	env, err := sealed.NewEnvelope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	mem := memstore.New()
	az := authz.New(mem)
	auth := ca.New(mem, env)
	aw := audit.NewWriter(mem, nil)
	t.Cleanup(aw.Close)
	issueSvc := issue.New(mem, auth, env, az, aw, nil)
	enrollSvc := enroll.New(mem, issueSvc, az, aw, rejectTokens{}, enroll.Config{AutoApprove: true}, nil)
	hub := stream.NewHub(stream.NewMemory(), stream.Config{ReplayWindow: time.Minute, StreamsPerUser: 5, StreamsPerTenant: 20, RetryDelay: time.Millisecond, ReadBlock: 10 * time.Millisecond}, nil)
	t.Cleanup(hub.Close)

	// A default self-signed issuer so issuance resolves.
	if _, err := issueSvc.CreateIssuer(context.Background(), adminSubj(), issue.IssuerInput{Name: "root", Type: "self_signed", TrustDomain: gTrustTD, IsDefault: true, Enabled: true}); err != nil {
		t.Fatalf("create issuer: %v", err)
	}

	return &gfixture{
		svid:   &SVIDServer{Svc: issueSvc, CA: auth, Repo: mem},
		enroll: &EnrollmentServer{Svc: enrollSvc},
		events: &EventsServer{Hub: hub},
		agent:  &AgentServer{Hub: hub},
		az:     az, mem: mem, hub: hub,
	}
}

type rejectTokens struct{}

func (rejectTokens) VerifyEnrollment(context.Context, string) (enroll.EnrollGrant, error) {
	return enroll.EnrollGrant{}, authz.ErrForbidden
}

func adminSubj() authz.Subjects {
	return authz.Subjects{TenantID: gTenant, UserID: "22222222-2222-7222-8222-222222222222", Roles: []string{"admin"}}
}

// withCaller sets callerFunc to name spiffe for the duration of fn.
func withCaller(spiffe string, ok bool, fn func()) {
	orig := callerFunc
	callerFunc = func(context.Context) (string, bool) { return spiffe, ok }
	defer func() { callerFunc = orig }()
	fn()
}

func TestSVIDLifecycle(t *testing.T) {
	f := newGRPC(t)
	ctx := context.Background()

	withCaller(gSpiffe, true, func() {
		// Issue for the caller's own SVID (entitled by identity match).
		b, err := f.svid.Issue(ctx, &lcmv1.IssueRequest{TenantId: gTenant, SpiffeId: gSpiffe})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if b.GetCertificate().GetId() == "" || b.GetCertPem() == "" {
			t.Fatalf("empty bundle: %+v", b)
		}
		certID := b.GetCertificate().GetId()
		serial := b.GetCertificate().GetSerial()

		// Grant tenant-wide owner so the service can renew (use) and revoke (delete).
		if _, err := f.az.Grant(ctx, adminSubj(), authz.GrantInput{ResourceType: authz.Certificate, ResourceID: certID, SubjectType: authz.SubjectTenant, Relation: authz.Owner}); err != nil {
			t.Fatalf("grant: %v", err)
		}

		// Verify: valid.
		vr, err := f.svid.Verify(ctx, &lcmv1.VerifyRequest{TenantId: gTenant, SpiffeId: gSpiffe, Serial: serial})
		if err != nil || !vr.GetValid() {
			t.Fatalf("Verify valid: %+v %v", vr, err)
		}

		// Trust bundle.
		tb, err := f.svid.GetTrustBundle(ctx, &lcmv1.TrustBundleRequest{TenantId: gTenant, TrustDomain: gTrustTD})
		if err != nil || tb.GetBundlePem() == "" {
			t.Fatalf("GetTrustBundle: %+v %v", tb, err)
		}

		// Renew.
		if _, err := f.svid.Renew(ctx, &lcmv1.RenewRequest{TenantId: gTenant, CertificateId: certID}); err != nil {
			t.Fatalf("Renew: %v", err)
		}

		// Revoke, then Verify reports revoked.
		rr, err := f.svid.Revoke(ctx, &lcmv1.RevokeRequest{TenantId: gTenant, CertificateId: certID, Reason: "keyCompromise"})
		if err != nil || !rr.GetRevoked() {
			t.Fatalf("Revoke: %+v %v", rr, err)
		}
		vr, err = f.svid.Verify(ctx, &lcmv1.VerifyRequest{TenantId: gTenant, SpiffeId: gSpiffe, Serial: serial})
		if err != nil || vr.GetValid() {
			t.Fatalf("Verify after revoke: %+v %v", vr, err)
		}
		// Verify unknown serial -> no_certificate.
		vr, _ = f.svid.Verify(ctx, &lcmv1.VerifyRequest{TenantId: gTenant, SpiffeId: gSpiffe, Serial: "does-not-exist"})
		if vr.GetValid() || vr.GetReason() != "no_certificate" {
			t.Fatalf("verify unknown serial: %+v", vr)
		}
	})
}

func TestSVIDUnauthenticatedAndBadTenant(t *testing.T) {
	f := newGRPC(t)
	ctx := context.Background()
	// No identity.
	withCaller("", false, func() {
		if _, err := f.svid.Issue(ctx, &lcmv1.IssueRequest{TenantId: gTenant, SpiffeId: gSpiffe}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("issue without identity: %v", err)
		}
	})
	// Identity present but tenant not a uuid.
	withCaller(gSpiffe, true, func() {
		if _, err := f.svid.Renew(ctx, &lcmv1.RenewRequest{TenantId: "not-a-uuid", CertificateId: "x"}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("bad tenant: %v", err)
		}
	})
}

func TestSVIDVerifyNoRepo(t *testing.T) {
	f := newGRPC(t)
	f.svid.Repo = nil
	withCaller(gSpiffe, true, func() {
		if _, err := f.svid.Verify(context.Background(), &lcmv1.VerifyRequest{TenantId: gTenant, SpiffeId: gSpiffe}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("verify no repo: %v", err)
		}
	})
}

func TestEnrollmentServer(t *testing.T) {
	f := newGRPC(t)
	ctx := context.Background()
	withCaller(gSpiffe, true, func() {
		// Auto-approve issues inline for the caller's own identity.
		b, err := f.enroll.Enroll(ctx, &lcmv1.EnrollRequest{TenantId: gTenant, SpiffeId: gSpiffe})
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if b.GetCertificate().GetId() == "" {
			t.Fatalf("empty enroll bundle")
		}
		// Unauthenticated.
	})
	withCaller("", false, func() {
		if _, err := f.enroll.Enroll(ctx, &lcmv1.EnrollRequest{TenantId: gTenant, SpiffeId: gSpiffe}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("enroll without identity: %v", err)
		}
	})
}

func TestEventsPublish(t *testing.T) {
	f := newGRPC(t)
	ctx := context.Background()
	withCaller(gSpiffe, true, func() {
		resp, err := f.events.Publish(ctx, &lcmv1.PublishRequest{TenantId: gTenant, All: true, Type: "workload.updated", Data: []byte(`{"certificate_id":"c1"}`)})
		if err != nil || resp.GetEventId() == "" {
			t.Fatalf("Publish: %+v %v", resp, err)
		}
	})
	withCaller("", false, func() {
		if _, err := f.events.Publish(ctx, &lcmv1.PublishRequest{TenantId: gTenant, Type: "x"}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("publish without identity: %v", err)
		}
	})
}

// fakeWatchServer captures the events Send'd by Agent.Watch.
type fakeWatchServer struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *lcmv1.CertificateUpdate
}

func (f *fakeWatchServer) Context() context.Context { return f.ctx }
func (f *fakeWatchServer) Send(u *lcmv1.CertificateUpdate) error {
	f.sent <- u
	return nil
}

func TestAgentWatchReceivesEvent(t *testing.T) {
	f := newGRPC(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &fakeWatchServer{ctx: ctx, sent: make(chan *lcmv1.CertificateUpdate, 4)}
	done := make(chan error, 1)
	withCaller(gSpiffe, true, func() {
		go func() { done <- f.agent.Watch(&lcmv1.WatchRequest{TenantId: gTenant}, srv) }()
		// Publish an event addressed to the caller (all=true reaches everyone).
		time.Sleep(20 * time.Millisecond)
		na := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, _ = f.hub.PublishID(context.Background(), gTenant, nil, true, "issued",
			map[string]any{"certificate_id": "c1", "spiffe_id": gSpiffe, "not_after": na}, false)
		select {
		case u := <-srv.sent:
			if u.GetCertificateId() != "c1" || u.GetSpiffeId() != gSpiffe {
				t.Fatalf("update: %+v", u)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no event received")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not return")
		}
	})
}

func TestAgentWatchUnauthenticated(t *testing.T) {
	f := newGRPC(t)
	srv := &fakeWatchServer{ctx: context.Background(), sent: make(chan *lcmv1.CertificateUpdate, 1)}
	withCaller("", false, func() {
		if err := f.agent.Watch(&lcmv1.WatchRequest{TenantId: gTenant}, srv); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("watch without identity: %v", err)
		}
	})
	withCaller(gSpiffe, true, func() {
		if err := f.agent.Watch(&lcmv1.WatchRequest{TenantId: "bad"}, srv); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("watch bad tenant: %v", err)
		}
	})
}

func TestGRPCErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want codes.Code
	}{
		{authz.ErrForbidden, codes.PermissionDenied},
		{authz.ErrNotFound, codes.NotFound},
		{store.ErrNotFound, codes.NotFound},
		{authz.ErrInput, codes.InvalidArgument},
		{store.ErrConflict, codes.AlreadyExists},
		{context.DeadlineExceeded, codes.Unavailable},
	}
	for _, c := range cases {
		if got := status.Code(grpcError(c.err)); got != c.want {
			t.Errorf("grpcError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestServiceCallerAndRegister(t *testing.T) {
	withCaller(gSpiffe, true, func() {
		if id, ok := ServiceCaller(context.Background()); !ok || id != gSpiffe {
			t.Fatalf("ServiceCaller: %q %v", id, ok)
		}
	})
	// Register mounts all four servers without panicking.
	f := newGRPC(t)
	reg := &recordingRegistrar{}
	Register(reg, Deps{Issue: f.svid.Svc, Enroll: f.enroll.Svc, CA: f.svid.CA, Repo: f.mem, Hub: f.hub})
	if reg.n < 4 {
		t.Fatalf("registered %d services, want >= 4", reg.n)
	}
}

type recordingRegistrar struct{ n int }

func (r *recordingRegistrar) RegisterService(*grpc.ServiceDesc, any) { r.n++ }
