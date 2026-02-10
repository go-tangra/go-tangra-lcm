package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/conf"
	"github.com/go-tangra/go-tangra-lcm/internal/data"
	appViewer "github.com/go-tangra/go-tangra-common/viewer"
)

// BootstrapService implements the LcmBootstrapService gRPC service
type BootstrapService struct {
	commonV1.UnimplementedLcmBootstrapServiceServer
	config     *conf.LCM
	certRepo   *data.MtlsCertificateRepo
	clientRepo *data.LcmClientRepo
	log        *log.Helper
}

// NewBootstrapService creates a new BootstrapService
func NewBootstrapService(
	ctx *bootstrap.Context,
	config *conf.LCM,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
) *BootstrapService {
	return &BootstrapService{
		config:     config,
		certRepo:   certRepo,
		clientRepo: clientRepo,
		log:        ctx.NewLoggerHelper("lcm/bootstrap-service"),
	}
}

// BootstrapCertificates generates and returns CA, client, and server certificates for a module
func (s *BootstrapService) BootstrapCertificates(ctx context.Context, req *commonV1.BootstrapCertificatesRequest) (*commonV1.BootstrapCertificatesResponse, error) {
	// Validate secret
	if req.GetSecret() != s.config.GetModuleRegistrationSecret() {
		return nil, status.Errorf(codes.Unauthenticated, "invalid module registration secret")
	}

	moduleID := req.GetModuleId()
	if moduleID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "module_id is required")
	}

	s.log.Infof("Bootstrap certificate request from module: %s", moduleID)

	// Bypass ent privacy checks
	ctx = appViewer.NewSystemViewerContext(ctx)

	// Load Root CA
	caCert, caKey, err := s.loadRootCA()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load root CA: %v", err)
	}

	// Read CA PEM for response
	caCertPEM, err := os.ReadFile(s.config.GetCaCertPath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read CA certificate: %v", err)
	}

	// Generate client certificate
	clientID := fmt.Sprintf("lcm-%s", moduleID)
	displayName := fmt.Sprintf("LCM %s", capitalize(moduleID))

	clientCertPEM, clientKeyPEM, err := s.generateClientCert(ctx, caCert, caKey, clientID, displayName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate client certificate: %v", err)
	}

	// Generate server certificate
	serverCertPEM, serverKeyPEM, err := s.generateServerCert(ctx, caCert, caKey, moduleID, req.GetDnsNames(), req.GetIpAddresses())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate server certificate: %v", err)
	}

	// Save to data_dir as well (for volume-mount compatibility)
	s.saveToDisk(moduleID, clientID, displayName, caCertPEM, clientCertPEM, clientKeyPEM, serverCertPEM, serverKeyPEM)

	s.log.Infof("Bootstrap certificates generated for module: %s", moduleID)

	return &commonV1.BootstrapCertificatesResponse{
		CaCertificatePem:     string(caCertPEM),
		ClientCertificatePem: clientCertPEM,
		ClientKeyPem:         clientKeyPEM,
		ServerCertificatePem: serverCertPEM,
		ServerKeyPem:         serverKeyPEM,
		Message:              fmt.Sprintf("Certificates generated for module %s", moduleID),
	}, nil
}

func (s *BootstrapService) generateClientCert(ctx context.Context, caCert *x509.Certificate, caKey any, clientID, displayName string) (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := s.generateSerialNumber(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{displayName},
			CommonName:         clientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	// Save to database (non-fatal)
	cert, parseErr := x509.ParseCertificate(certDER)
	if parseErr == nil {
		s.saveClientCertToDatabase(ctx, cert, key, serialNumber, clientID)
	}

	return string(certPEMBytes), string(keyPEMBytes), nil
}

func (s *BootstrapService) generateServerCert(ctx context.Context, caCert *x509.Certificate, caKey any, moduleID string, dnsNames, ipAddressStrs []string) (certPEM, keyPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := s.generateSerialNumber(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	var ipAddresses []net.IP
	for _, ipStr := range ipAddressStrs {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}
	// Always include loopback
	ipAddresses = append(ipAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

	serviceName := fmt.Sprintf("%s-service", moduleID)
	displayName := fmt.Sprintf("%s Service", capitalize(moduleID))

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{displayName},
			CommonName:         serviceName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create server certificate: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	return string(certPEMBytes), string(keyPEMBytes), nil
}

func (s *BootstrapService) loadRootCA() (*x509.Certificate, any, error) {
	caCertPEM, err := os.ReadFile(s.config.GetCaCertPath())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(s.config.GetCaKeyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	var caKey any
	switch caKeyBlock.Type {
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported CA key type: %s", caKeyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return caCert, caKey, nil
}

func (s *BootstrapService) generateSerialNumber(ctx context.Context) (int64, error) {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	for i := 0; i < 100; i++ {
		serialNumber := timestamp + int64(i)
		exists, err := s.certRepo.IsExistBySerialNumber(ctx, serialNumber)
		if err != nil {
			return timestamp, nil
		}
		if !exists {
			return serialNumber, nil
		}
	}
	return 0, fmt.Errorf("failed to generate unique serial number after 100 attempts")
}

func (s *BootstrapService) saveClientCertToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64, clientID string) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		s.log.Warnf("Failed to marshal public key: %v", err)
		return
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(clientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr("lcm-root-ca"),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	if _, err := s.certRepo.Create(ctx, certData); err != nil {
		s.log.Warnf("Failed to save %s certificate to database (non-fatal): %v", clientID, err)
	}

	// Ensure client entry exists
	existingClient, _ := s.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if existingClient == nil {
		moduleType := clientID[4:] // strip "lcm-" prefix
		if _, err := s.clientRepo.Create(ctx, 0, clientID, map[string]string{
			"type":        moduleType,
			"description": fmt.Sprintf("LCM %s Client (auto-generated via bootstrap)", capitalize(moduleType)),
		}); err != nil {
			s.log.Warnf("Failed to create LcmClient entry for %s (non-fatal): %v", clientID, err)
		}
	}
}

func (s *BootstrapService) saveToDisk(moduleID string, clientID, displayName string, caCertPEM []byte, clientCertPEM, clientKeyPEM, serverCertPEM, serverKeyPEM string) {
	dataDir := s.config.GetDataDir()

	// Save client cert
	certDir := filepath.Join(dataDir, moduleID)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		s.log.Warnf("Failed to create cert dir %s: %v", certDir, err)
		return
	}
	certFile := filepath.Join(certDir, moduleID+".crt")
	keyFile := filepath.Join(certDir, moduleID+".key")
	if err := os.WriteFile(certFile, []byte(clientCertPEM), 0644); err != nil {
		s.log.Warnf("Failed to write client cert: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte(clientKeyPEM), 0600); err != nil {
		s.log.Warnf("Failed to write client key: %v", err)
	}

	// Save server cert
	serverDir := filepath.Join(dataDir, moduleID+"-server")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		s.log.Warnf("Failed to create server cert dir %s: %v", serverDir, err)
		return
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.crt"), []byte(serverCertPEM), 0644); err != nil {
		s.log.Warnf("Failed to write server cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.key"), []byte(serverKeyPEM), 0600); err != nil {
		s.log.Warnf("Failed to write server key: %v", err)
	}
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	}
	return string(b)
}
