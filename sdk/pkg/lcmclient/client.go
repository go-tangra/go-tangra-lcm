// Package lcmclient is the workload-side client library for the lcm
// certificate & SVID lifecycle module. It talks to the module over the Freya
// SPIFFE mTLS gRPC channel using the generated lcm.v1 API.
//
// The package is intentionally transport-agnostic: New takes an already-dialed
// grpc.ClientConnInterface (the caller supplies the SPIFFE-mTLS connection, e.g.
// via freya.App.Client(ctx, "lcm")). This keeps lcmclient testable and
// dependency-light — an in-process bufconn server is enough to exercise it.
package lcmclient

import (
	"context"
	"errors"
	"io"
	"time"

	lcmv1 "github.com/go-tangra/go-tangra-lcm/sdk/v4/api/proto/lcm/v1"
	"google.golang.org/grpc"
)

// Client wraps the four generated lcm.v1 gRPC service clients and exposes
// ergonomic, proto-free methods.
type Client struct {
	svid   lcmv1.SVIDClient
	enroll lcmv1.EnrollmentClient
	events lcmv1.EventsClient
	agent  lcmv1.AgentClient
}

// New builds a Client over an established connection. conn is typically a
// *grpc.ClientConn dialed on the Freya SPIFFE mTLS channel, but any
// grpc.ClientConnInterface (e.g. a bufconn dial in tests) works.
func New(conn grpc.ClientConnInterface) *Client {
	return &Client{
		svid:   lcmv1.NewSVIDClient(conn),
		enroll: lcmv1.NewEnrollmentClient(conn),
		events: lcmv1.NewEventsClient(conn),
		agent:  lcmv1.NewAgentClient(conn),
	}
}

// EnrollRequest is the input to Enroll: a first-SVID request for a new workload.
type EnrollRequest struct {
	TenantID        string
	SpiffeID        string
	CSRPEM          string // signs the caller's key; empty => module generates the key
	EnrollmentToken string // auth-minted; empty when enrolling with the caller identity
}

// IssueRequest is the input to Issue: mint an SVID the caller is entitled to.
type IssueRequest struct {
	TenantID        string
	IssuerID        string // default issuer when empty
	SpiffeID        string
	CSRPEM          string // sign this CSR; otherwise the module generates the key
	DNSSANs         []string
	ValiditySeconds int64
	CorrelationID   string
}

// Bundle is a Go-friendly view of a lcm.v1.CertificateBundle. KeyPEM is set only
// when the module generated the private key.
type Bundle struct {
	CertPEM   string
	ChainPEM  string
	BundlePEM string // trust roots
	KeyPEM    string // present only when the module generated the key

	Serial   string
	SpiffeID string
	NotAfter time.Time
}

// Update is a Go-friendly view of a lcm.v1.CertificateUpdate streamed by Watch.
type Update struct {
	Type          string // issued | renewed | revoked
	CertificateID string
	SpiffeID      string
	NotAfter      time.Time
}

// bundleFrom maps a proto CertificateBundle to a Bundle.
func bundleFrom(b *lcmv1.CertificateBundle) *Bundle {
	if b == nil {
		return nil
	}
	out := &Bundle{
		CertPEM:   b.GetCertPem(),
		ChainPEM:  b.GetChainPem(),
		BundlePEM: b.GetBundlePem(),
		KeyPEM:    b.GetKeyPem(),
	}
	if c := b.GetCertificate(); c != nil {
		out.Serial = c.GetSerial()
		out.SpiffeID = c.GetSpiffeId()
		if ts := c.GetNotAfter(); ts != nil {
			out.NotAfter = ts.AsTime()
		}
	}
	return out
}

// Enroll obtains the first SVID for a new workload.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*Bundle, error) {
	resp, err := c.enroll.Enroll(ctx, &lcmv1.EnrollRequest{
		TenantId:        req.TenantID,
		SpiffeId:        req.SpiffeID,
		CsrPem:          req.CSRPEM,
		EnrollmentToken: req.EnrollmentToken,
	})
	if err != nil {
		return nil, err
	}
	return bundleFrom(resp), nil
}

// Issue mints an SVID for a SPIFFE id the caller is entitled to.
func (c *Client) Issue(ctx context.Context, req IssueRequest) (*Bundle, error) {
	resp, err := c.svid.Issue(ctx, &lcmv1.IssueRequest{
		TenantId:        req.TenantID,
		IssuerId:        req.IssuerID,
		SpiffeId:        req.SpiffeID,
		CsrPem:          req.CSRPEM,
		DnsSans:         req.DNSSANs,
		ValiditySeconds: req.ValiditySeconds,
		CorrelationId:   req.CorrelationID,
	})
	if err != nil {
		return nil, err
	}
	return bundleFrom(resp), nil
}

// Renew reissues an existing certificate with the same SPIFFE id. tenantID may
// be empty when the module derives it from the verified identity; pass certID as
// the certificate to renew.
func (c *Client) Renew(ctx context.Context, certID string) (*Bundle, error) {
	return c.RenewTenant(ctx, "", certID)
}

// RenewTenant is Renew with an explicit tenant id.
func (c *Client) RenewTenant(ctx context.Context, tenantID, certID string) (*Bundle, error) {
	resp, err := c.svid.Renew(ctx, &lcmv1.RenewRequest{
		TenantId:      tenantID,
		CertificateId: certID,
	})
	if err != nil {
		return nil, err
	}
	return bundleFrom(resp), nil
}

// Revoke revokes a certificate and publishes the revocation.
func (c *Client) Revoke(ctx context.Context, certID, reason string) error {
	return c.RevokeTenant(ctx, "", certID, reason)
}

// RevokeTenant is Revoke with an explicit tenant id.
func (c *Client) RevokeTenant(ctx context.Context, tenantID, certID, reason string) error {
	_, err := c.svid.Revoke(ctx, &lcmv1.RevokeRequest{
		TenantId:      tenantID,
		CertificateId: certID,
		Reason:        reason,
	})
	return err
}

// Verify reports whether the certificate with the given serial is currently
// valid (not expired, not revoked).
func (c *Client) Verify(ctx context.Context, serial string) (bool, error) {
	return c.VerifyTenant(ctx, "", serial)
}

// VerifyTenant is Verify with an explicit tenant id.
func (c *Client) VerifyTenant(ctx context.Context, tenantID, serial string) (bool, error) {
	resp, err := c.svid.Verify(ctx, &lcmv1.VerifyRequest{
		TenantId: tenantID,
		Serial:   serial,
	})
	if err != nil {
		return false, err
	}
	return resp.GetValid(), nil
}

// TrustBundle returns the PEM-encoded trust roots for a trust domain.
func (c *Client) TrustBundle(ctx context.Context, trustDomain string) (string, error) {
	return c.TrustBundleTenant(ctx, "", trustDomain)
}

// TrustBundleTenant is TrustBundle with an explicit tenant id.
func (c *Client) TrustBundleTenant(ctx context.Context, tenantID, trustDomain string) (string, error) {
	resp, err := c.svid.GetTrustBundle(ctx, &lcmv1.TrustBundleRequest{
		TenantId:    tenantID,
		TrustDomain: trustDomain,
	})
	if err != nil {
		return "", err
	}
	return resp.GetBundlePem(), nil
}

// Watch opens the Agent.Watch server stream and invokes handler once per
// CertificateUpdate until ctx is done or the stream ends. Reconnecting on error
// is the caller's job (see RunAgent for a loop that does it). A clean end of
// stream (io.EOF) and a ctx cancellation both return nil.
func (c *Client) Watch(ctx context.Context, lastEventID string, handler func(Update)) error {
	return c.WatchTenant(ctx, "", lastEventID, handler)
}

// WatchTenant is Watch with an explicit tenant id.
func (c *Client) WatchTenant(ctx context.Context, tenantID, lastEventID string, handler func(Update)) error {
	stream, err := c.agent.Watch(ctx, &lcmv1.WatchRequest{
		TenantId:    tenantID,
		LastEventId: lastEventID,
	})
	if err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		u := Update{
			Type:          msg.GetType(),
			CertificateID: msg.GetCertificateId(),
			SpiffeID:      msg.GetSpiffeId(),
		}
		if ts := msg.GetNotAfter(); ts != nil {
			u.NotAfter = ts.AsTime()
		}
		handler(u)
	}
}

// Publish emits a lifecycle event to the tenant stream and returns the event id.
// data must be JSON with no key material.
func (c *Client) Publish(ctx context.Context, tenantID, eventType string, data []byte, userIDs []string, all bool) (string, error) {
	resp, err := c.events.Publish(ctx, &lcmv1.PublishRequest{
		TenantId: tenantID,
		UserIds:  userIDs,
		All:      all,
		Type:     eventType,
		Data:     data,
	})
	if err != nil {
		return "", err
	}
	return resp.GetEventId(), nil
}
