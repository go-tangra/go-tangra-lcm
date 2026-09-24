package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/issue"
)

// CertDeps are the services behind the issuer and certificate routes.
type CertDeps struct {
	Issue *issue.Service
	Perms PermissionChecker
	// Pub fans a lifecycle event (issued|renewed|revoked) out to the tenant's
	// live streams; nil disables live publishing.
	Pub func(ctx context.Context, tenantID, eventType, certificateID, spiffeID string, notAfter time.Time)
	// PubFail fans a certificate.failed event (async issuance failure) to the tenant.
	PubFail func(ctx context.Context, tenantID string, detail map[string]any)
}

// issueError maps issue-service errors (validation, in-use) onto refusals in
// addition to the shared domainError mapping.
func issueError(err error) error {
	var ve *issue.ValidationError
	var iu *issue.InUseError
	switch {
	case errors.As(err, &ve):
		return &DetailError{Err: ErrValidation, Detail: map[string]any{"field": ve.Field, "message": ve.Message}}
	case errors.As(err, &iu):
		return &DetailError{Err: ErrConflict, Detail: map[string]any{iu.What: iu.Count}}
	}
	return domainError(err)
}

// issueReadError is issueError with not_found masking for single reads: an
// object the caller may not read answers not_found so existence never leaks
// (SR-005). The authz sentinel is checked before mapping wraps it.
func issueReadError(err error) error {
	if errors.Is(err, authz.ErrForbidden) {
		return ErrNotFound
	}
	return issueError(err)
}

// bundleJSON shapes an issue.Bundle as the OpenAPI CertificateBundle.
func bundleJSON(b issue.Bundle) map[string]any {
	m := map[string]any{
		"certificate": b.Certificate,
		"cert_pem":    b.CertPEM,
		"chain_pem":   b.ChainPEM,
		"bundle_pem":  b.BundlePEM,
	}
	if b.KeyPEM != "" {
		m["key_pem"] = b.KeyPEM
	}
	return m
}
