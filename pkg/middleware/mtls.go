package middleware

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-lcm/pkg/client"
)

// Use the shared ClientInfo type from pkg/client
type ClientInfo = client.ClientInfo

// MTLSMiddleware creates a mutual TLS authentication middleware
func MTLSMiddleware(logger log.Logger) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/mtls"))

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			// Get the transport info to determine the operation
			if tr, ok := transport.FromServerContext(ctx); ok {
				operation := tr.Operation()

				// Extract peer information from gRPC context
				var clientInfo *ClientInfo
				p, hasPeer := peer.FromContext(ctx)
				if hasPeer {
					clientInfo = extractClientInfo(p, l)
				}

				// If no mTLS client info, try to extract from gRPC metadata
				// (set by admin-service when proxying HTTP requests)
				if clientInfo == nil || !clientInfo.IsAuthenticated {
					if mdInfo := extractClientInfoFromMetadata(ctx, l); mdInfo != nil {
						clientInfo = mdInfo
					}
				}

				// Skip mTLS for public endpoints
				if isPublicEndpoint(operation) {
					l.Debugf("Skipping mTLS for public endpoint: %s", operation)
					ctx = context.WithValue(ctx, client.ClientInfoKey, clientInfo)
					return handler(ctx, req)
				}

				// Validate authentication for protected endpoints
				if clientInfo == nil || !clientInfo.IsAuthenticated {
					l.Error("Authentication failed: no valid certificate or metadata")
					return nil, status.Error(codes.Unauthenticated, "client certificate required for this endpoint")
				}

				l.Debugf("Client authenticated for operation: %s (CN: %s)", operation, clientInfo.CommonName)

				// Add client info to context
				ctx = context.WithValue(ctx, client.ClientInfoKey, clientInfo)
			}

			return handler(ctx, req)
		}
	}
}

// isPublicEndpoint checks if the given operation is a public endpoint that doesn't require mTLS
func isPublicEndpoint(operation string) bool {
	publicEndpoints := []string{
		"/lcm.service.v1.LcmClientService/DownloadClientCertificate",
		"/lcm.service.v1.LcmClientService/GetRequestStatus",
		"/lcm.service.v1.LcmClientService/RegisterLcmClient",
		"/lcm.service.v1.ClientService/Register",
		"/lcm.service.v1.ClientService/DownloadClientCert",
		"/lcm.service.v1.SystemService/HealthCheck",
	}

	return slices.Contains(publicEndpoints, operation)
}

// extractClientInfoFromMetadata creates a ClientInfo from gRPC metadata headers
// injected by the admin-service when proxying HTTP requests to module services.
func extractClientInfoFromMetadata(ctx context.Context, l *log.Helper) *ClientInfo {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	// Check for admin-service metadata headers
	userID := getMetadataValue(md, "x-md-global-user-id")
	username := getMetadataValue(md, "x-md-global-username")
	tenantIDStr := getMetadataValue(md, "x-md-global-tenant-id")

	// Need at least user ID or username to create a valid identity
	if userID == "" && username == "" {
		return nil
	}

	// Use username as CommonName (client identity), fall back to user ID
	cn := username
	if cn == "" {
		cn = userID
	}

	var tenantID uint32
	if tenantIDStr != "" {
		if v, err := strconv.ParseUint(tenantIDStr, 10, 32); err == nil {
			tenantID = uint32(v)
		}
	}

	l.Debugf("Authenticated via metadata: username=%s, user_id=%s, tenant_id=%d", username, userID, tenantID)

	return &ClientInfo{
		CommonName:      cn,
		IsAuthenticated: true,
		TenantID:        tenantID,
	}
}

// getMetadataValue extracts a single value from gRPC metadata
func getMetadataValue(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// extractClientInfo extracts and validates client certificate information from peer
func extractClientInfo(p *peer.Peer, l *log.Helper) *ClientInfo {
	// Check if the connection has TLS info
	if p.AuthInfo == nil {
		l.Debug("No TLS authentication info available")
		return nil
	}

	// Cast to TLS credentials to access certificate information
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		l.Debug("Failed to cast to TLS credentials")
		return nil
	}

	// Check if client certificates are present
	if len(tlsInfo.State.PeerCertificates) == 0 {
		l.Debug("No client certificates provided")
		return nil
	}

	// Get the first (leaf) certificate
	clientCert := tlsInfo.State.PeerCertificates[0]

	// Create client info struct
	clientInfo := &ClientInfo{
		Certificate:     clientCert,
		Subject:         clientCert.Subject.String(),
		Issuer:          clientCert.Issuer.String(),
		SerialNumber:    clientCert.SerialNumber.String(),
		CommonName:      clientCert.Subject.CommonName,
		Organizations:   clientCert.Subject.Organization,
		NotBefore:       clientCert.NotBefore,
		NotAfter:        clientCert.NotAfter,
		IsAuthenticated: false, // Will be set to true after validation
	}

	// Validate certificate
	if err := validateCertificateValidity(clientCert); err != nil {
		l.Debugf("Certificate validity check failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	if err := validateCertificateIssuer(clientCert); err != nil {
		l.Debugf("Certificate issuer validation failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	// Mark as authenticated if all validations pass
	clientInfo.IsAuthenticated = true

	return clientInfo
}

// GetClientInfoFromContext extracts client information from the request context
// This function now delegates to the shared client package
func GetClientInfoFromContext(ctx context.Context) (*ClientInfo, bool) {
	return client.GetClientInfoFromContext(ctx)
}

// GetClientCertificateFromContext extracts the client certificate from the request context
// This function now delegates to the shared client package
func GetClientCertificateFromContext(ctx context.Context) (*x509.Certificate, bool) {
	return client.GetClientCertificateFromContext(ctx)
}

// IsClientAuthenticated checks if the client is authenticated via mTLS
// This function now delegates to the shared client package
func IsClientAuthenticated(ctx context.Context) bool {
	return client.IsClientAuthenticated(ctx)
}

// validateCertificateValidity checks if the certificate is currently valid
func validateCertificateValidity(cert *x509.Certificate) error {
	now := time.Now()
	if cert.NotBefore.After(now) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if cert.NotAfter.Before(now) {
		return fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
	}
	return nil
}

// validateCertificateIssuer checks if the certificate was issued by our CA
func validateCertificateIssuer(cert *x509.Certificate) error {
	// Check if the issuer contains "LCM" which should be present in our CA
	issuerStr := cert.Issuer.String()
	if issuerStr == "" {
		return fmt.Errorf("certificate has no issuer information")
	}

	// Simple check - in production you might want to verify against the actual CA certificate
	expectedOrgUnits := []string{"LCM Certificate Authority", "LCM"}
	for _, ou := range cert.Issuer.OrganizationalUnit {
		if slices.Contains(expectedOrgUnits, ou) {
			return nil // Valid issuer
		}
	}

	// Check organization as well
	if slices.Contains(cert.Issuer.Organization, "LCM") {
		return nil // Valid issuer
	}

	return fmt.Errorf("certificate not issued by trusted CA (issuer: %s)", issuerStr)
}

// ExtractClientCertificate extracts the client certificate from the context
// This function is now implemented using the mTLS middleware context
func ExtractClientCertificate(ctx context.Context) (*x509.Certificate, error) {
	if cert, ok := GetClientCertificateFromContext(ctx); ok {
		return cert, nil
	}
	return nil, errors.New(401, "NO_CLIENT_CERT", "no client certificate found in context")
}
