package grpcapi

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmv1 "github.com/go-freya/freya/services/lcm/api/proto/lcm/v1"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/enroll"
	"github.com/go-freya/freya/services/lcm/internal/issue"
	"github.com/go-freya/freya/services/lcm/internal/store"
	"github.com/go-freya/freya/services/lcm/internal/stream"
)

// Repo is the read access the SVID Verify method needs (repo.Store satisfies it).
type Repo interface {
	ListCertificates(ctx context.Context, tenantID string, f store.CertificateFilter) ([]store.IssuedCertificate, error)
}

// ---- SVID

// SVIDServer implements lcm.v1.SVID for modules and workloads.
type SVIDServer struct {
	lcmv1.UnimplementedSVIDServer
	Svc  *issue.Service
	CA   *ca.Authority
	Repo Repo
}

func (s *SVIDServer) Issue(ctx context.Context, req *lcmv1.IssueRequest) (*lcmv1.CertificateBundle, error) {
	subj, err := caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	b, err := s.Svc.Issue(ctx, subj, issue.IssueInput{IssuerID: req.GetIssuerId(), SpiffeID: req.GetSpiffeId(), CSRPEM: req.GetCsrPem(), DNSSans: req.GetDnsSans(), ValiditySeconds: req.GetValiditySeconds(), DeliverKey: req.GetCsrPem() == ""})
	if err != nil {
		return nil, grpcError(err)
	}
	return toBundle(b), nil
}

func (s *SVIDServer) Renew(ctx context.Context, req *lcmv1.RenewRequest) (*lcmv1.CertificateBundle, error) {
	subj, err := caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	b, err := s.Svc.Renew(ctx, subj, req.GetCertificateId())
	if err != nil {
		return nil, grpcError(err)
	}
	return toBundle(b), nil
}

func (s *SVIDServer) Revoke(ctx context.Context, req *lcmv1.RevokeRequest) (*lcmv1.RevokeResponse, error) {
	subj, err := caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if err := s.Svc.Revoke(ctx, subj, req.GetCertificateId(), req.GetReason()); err != nil {
		return nil, grpcError(err)
	}
	return &lcmv1.RevokeResponse{Revoked: true}, nil
}

func (s *SVIDServer) Verify(ctx context.Context, req *lcmv1.VerifyRequest) (*lcmv1.VerifyResponse, error) {
	if _, err := caller(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	if s.Repo == nil {
		return nil, status.Error(codes.Unimplemented, "verify unavailable")
	}
	// Look up candidates by SPIFFE id (the common case) and report the status.
	certs, err := s.Repo.ListCertificates(ctx, req.GetTenantId(), store.CertificateFilter{SpiffeID: req.GetSpiffeId(), Limit: 50})
	if err != nil {
		return nil, grpcError(err)
	}
	now := time.Now()
	for _, c := range certs {
		if req.GetSerial() != "" && c.Serial != req.GetSerial() {
			continue
		}
		st := derived(c, now)
		if st == "revoked" {
			return &lcmv1.VerifyResponse{Valid: false, Reason: "revoked"}, nil
		}
		if st == "expired" {
			continue
		}
		return &lcmv1.VerifyResponse{Valid: true, Reason: "ok"}, nil
	}
	return &lcmv1.VerifyResponse{Valid: false, Reason: "no_certificate"}, nil
}

func (s *SVIDServer) GetTrustBundle(ctx context.Context, req *lcmv1.TrustBundleRequest) (*lcmv1.TrustBundleResponse, error) {
	if _, err := caller(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	pem, err := s.CA.Bundle(ctx, req.GetTenantId(), req.GetTrustDomain())
	if err != nil {
		return nil, grpcError(err)
	}
	return &lcmv1.TrustBundleResponse{BundlePem: pem}, nil
}

// derived returns the read-time status of a certificate.
func derived(c store.IssuedCertificate, now time.Time) string {
	if c.Status == "revoked" {
		return "revoked"
	}
	if now.After(c.NotAfter) {
		return "expired"
	}
	return "active"
}

// ---- Enrollment

// EnrollmentServer implements lcm.v1.Enrollment for new workloads.
type EnrollmentServer struct {
	lcmv1.UnimplementedEnrollmentServer
	Svc *enroll.Service
}

func (s *EnrollmentServer) Enroll(ctx context.Context, req *lcmv1.EnrollRequest) (*lcmv1.CertificateBundle, error) {
	subj, err := caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	res, err := s.Svc.Enroll(ctx, subj, enroll.EnrollInput{SpiffeID: req.GetSpiffeId(), CSRPEM: req.GetCsrPem(), EnrollmentToken: req.GetEnrollmentToken()})
	if err != nil {
		return nil, grpcError(err)
	}
	if res.Status != "issued" || res.Bundle == nil {
		return nil, status.Error(codes.FailedPrecondition, "enrollment requires manual approval")
	}
	return toBundle(*res.Bundle), nil
}

// ---- Events

// EventsServer implements lcm.v1.Events (other modules publish lifecycle events).
type EventsServer struct {
	lcmv1.UnimplementedEventsServer
	Hub *stream.Hub
}

func (s *EventsServer) Publish(ctx context.Context, req *lcmv1.PublishRequest) (*lcmv1.PublishResponse, error) {
	if _, err := caller(ctx, req.GetTenantId()); err != nil {
		return nil, err
	}
	var data any
	if len(req.GetData()) > 0 {
		data = json.RawMessage(req.GetData())
	}
	id, err := s.Hub.PublishID(ctx, req.GetTenantId(), req.GetUserIds(), req.GetAll(), req.GetType(), data, true)
	if err != nil {
		return nil, grpcError(err)
	}
	return &lcmv1.PublishResponse{EventId: id}, nil
}

// ---- Agent (streaming)

// AgentServer implements lcm.v1.Agent: a workload watches live certificate
// updates and rotates its SVID with no downtime.
type AgentServer struct {
	lcmv1.UnimplementedAgentServer
	Hub *stream.Hub
}

func (s *AgentServer) Watch(req *lcmv1.WatchRequest, srv lcmv1.Agent_WatchServer) error {
	ctx := srv.Context()
	id, ok := callerFunc(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "service identity required")
	}
	if !uuidRE.MatchString(req.GetTenantId()) {
		return status.Error(codes.InvalidArgument, "tenant_id must be a uuid")
	}
	sub, err := s.Hub.Subscribe(ctx, req.GetTenantId(), id, req.GetLastEventId())
	if err != nil {
		return grpcError(err)
	}
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-sub.Events():
			if !ok {
				return nil
			}
			upd := &lcmv1.CertificateUpdate{Id: ev.ID, Type: ev.Type}
			var payload struct {
				CertificateID string `json:"certificate_id"`
				SpiffeID      string `json:"spiffe_id"`
				NotAfter      string `json:"not_after"`
			}
			if json.Unmarshal([]byte(ev.Data), &payload) == nil {
				upd.CertificateId = payload.CertificateID
				upd.SpiffeId = payload.SpiffeID
				if t, err := time.Parse(time.RFC3339, payload.NotAfter); err == nil {
					upd.NotAfter = timestamppb.New(t)
				}
			}
			if err := srv.Send(upd); err != nil {
				return err
			}
		}
	}
}

// ---- helpers

func certStatus(s string) lcmv1.CertificateStatus {
	switch s {
	case "active":
		return lcmv1.CertificateStatus_CERTIFICATE_STATUS_ACTIVE
	case "expiring":
		return lcmv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRING
	case "expired":
		return lcmv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	case "revoked":
		return lcmv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED
	}
	return lcmv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED
}

// ---- Certificates

// CertificatesServer implements lcm.v1.Certificates: it hands an already-issued
// certificate (cert + chain + retained key) to an authorized platform module
// for deployment. The caller is a verified service (mTLS, policed by
// policy.yaml); authorization is by the caller policy, not a user grant.
type CertificatesServer struct {
	lcmv1.UnimplementedCertificatesServer
	Svc *issue.Service
}

// Download returns the certificate bundle for the request's certificate id in
// the named tenant, including the retained private key when include_key is set.
func (s *CertificatesServer) Download(ctx context.Context, req *lcmv1.DownloadRequest) (*lcmv1.CertificateBundle, error) {
	subj, err := caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	b, err := s.Svc.DownloadForService(ctx, req.GetTenantId(), subj.Service, req.GetCertificateId(), req.GetIncludeKey())
	if err != nil {
		return nil, grpcError(err)
	}
	return toBundle(b), nil
}

func toBundle(b issue.Bundle) *lcmv1.CertificateBundle {
	return &lcmv1.CertificateBundle{
		Certificate: toCertificate(b.Certificate),
		CertPem:     b.CertPEM,
		ChainPem:    b.ChainPEM,
		BundlePem:   b.BundlePEM,
		KeyPem:      b.KeyPEM,
	}
}

func toCertificate(v issue.CertificateView) *lcmv1.Certificate {
	c := &lcmv1.Certificate{
		Id: v.ID, IssuerId: v.IssuerID, Serial: v.Serial, SpiffeId: v.SpiffeID,
		Subject: v.Subject, Sans: v.SANs, FingerprintSha256: v.FingerprintSHA256, Status: certStatus(v.Status),
	}
	if !v.NotBefore.IsZero() {
		c.NotBefore = timestamppb.New(v.NotBefore)
	}
	if !v.NotAfter.IsZero() {
		c.NotAfter = timestamppb.New(v.NotAfter)
	}
	return c
}
