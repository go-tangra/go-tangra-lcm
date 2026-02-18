package bootstrap

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
	"google.golang.org/protobuf/types/known/timestamppb"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/conf"
	"github.com/go-tangra/go-tangra-lcm/internal/data"
	appViewer "github.com/go-tangra/go-tangra-common/viewer"
)

const (
	// AdminClientID is the client_id for the auto-generated admin certificate
	AdminClientID = "lcm-admin"

	// ServerCertIssuer is the issuer name for the server certificate (used when signing admin certs)
	ServerCertIssuer = "lcm-server"

	// RootCAIssuer is the issuer name for the root CA
	RootCAIssuer = "lcm-root-ca"

	// Certificate directory names (relative to data_dir)
	ServerCertDir = "server"
	AdminCertDir  = "admin"
)

// BootstrapService handles initial certificate setup on server startup
type BootstrapService struct {
	config         *conf.LCM
	certRepo       *data.MtlsCertificateRepo
	clientRepo     *data.LcmClientRepo
	issuedCertRepo *data.IssuedCertificateRepo
	issuerRepo     *data.IssuerRepo
	log            *log.Helper
}

// NewBootstrapService creates a new bootstrap service
func NewBootstrapService(
	ctx *bootstrap.Context,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
	issuedCertRepo *data.IssuedCertificateRepo,
	issuerRepo *data.IssuerRepo,
) (*BootstrapService, error) {
	cfg, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil, fmt.Errorf("lcm config not found")
	}
	lcmConfig, ok := cfg.(*conf.LCM)
	if !ok {
		return nil, fmt.Errorf("invalid lcm config type")
	}

	return &BootstrapService{
		config:         lcmConfig,
		certRepo:       certRepo,
		clientRepo:     clientRepo,
		issuedCertRepo: issuedCertRepo,
		issuerRepo:     issuerRepo,
		log:            ctx.NewLoggerHelper("lcm/bootstrap"),
	}, nil
}

// Bootstrap performs the initial certificate setup
func (bs *BootstrapService) Bootstrap(ctx context.Context) error {
	// Wrap context with system viewer to bypass ent privacy checks during bootstrap
	ctx = appViewer.NewSystemViewerContext(ctx)
	bs.log.Info("Starting mTLS certificate bootstrap...")

	// Step 1: Ensure LCM server certificate exists (intermediate CA)
	_, _, err := bs.ensureServerCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure server certificate: %w", err)
	}

	// Step 2: Load root CA for signing all subsequent certificates
	caCert, caKey, err := bs.loadRootCA()
	if err != nil {
		return fmt.Errorf("failed to load root CA for cert signing: %w", err)
	}

	// Step 3: Ensure admin client certificate (always needed, special case)
	if err := bs.ensureAdminCertificate(ctx, caCert, caKey); err != nil {
		return fmt.Errorf("failed to ensure admin certificate: %w", err)
	}

	// Step 4: Loop over configured bootstrap modules
	for _, mod := range bs.config.GetBootstrapModules() {
		if err := bs.ensureModuleClientCertificate(ctx, caCert, caKey, mod); err != nil {
			return fmt.Errorf("failed to ensure %s client certificate: %w", mod.GetModuleId(), err)
		}
		if mod.GetServerCertDir() != "" {
			if err := bs.ensureModuleServerCertificate(ctx, caCert, caKey, mod); err != nil {
				return fmt.Errorf("failed to ensure %s server certificate: %w", mod.GetModuleId(), err)
			}
		}
	}

	// Step 5: Ensure frontend ACME certificate (non-fatal)
	if bs.config.GetFrontendCertificate() != nil && bs.config.GetFrontendCertificate().GetEnabled() {
		if err := bs.ensureFrontendCertificate(ctx); err != nil {
			bs.log.Warnf("Failed to ensure frontend certificate (non-fatal): %v", err)
		}
	}

	bs.log.Info("mTLS certificate bootstrap completed successfully")
	return nil
}

// ensureServerCertificate ensures the server certificate exists, generating it if necessary
func (bs *BootstrapService) ensureServerCertificate(ctx context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
	serverCertPath := filepath.Join(bs.config.GetDataDir(), ServerCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), ServerCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Info("Server certificate already exists in files, loading...")
		return bs.loadCertificateAndKey(serverCertPath, serverKeyPath)
	}

	bs.log.Info("Server certificate not found, generating new intermediate CA certificate...")

	caCert, caKey, err := bs.loadRootCA()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load root CA: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Server CA"},
			CommonName:         "lcm-server",
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	template.DNSNames = []string{"localhost", "lcm-server", "lcm-service", "*.local"}
	template.IPAddresses = []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv4(0, 0, 0, 0),
		net.IPv6loopback,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	serverCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return nil, nil, fmt.Errorf("failed to save server certificate to files: %w", err)
	}

	if err := bs.saveServerCertificateToDatabase(ctx, serverCert, serverKey, serialNumber); err != nil {
		bs.log.Warnf("Failed to save server certificate to database (non-fatal): %v", err)
	}

	bs.log.Infof("Generated server certificate with serial number: %d", serialNumber)
	return serverCert, serverKey, nil
}

// ensureAdminCertificate ensures the admin client certificate exists
func (bs *BootstrapService) ensureAdminCertificate(ctx context.Context, caCert *x509.Certificate, caKey any) error {
	adminCertPath := filepath.Join(bs.config.GetDataDir(), AdminCertDir, "admin.crt")
	adminKeyPath := filepath.Join(bs.config.GetDataDir(), AdminCertDir, "admin.key")

	if bs.certificatesExist(adminCertPath, adminKeyPath) {
		bs.log.Info("Admin certificate already exists in files")
		bs.ensureModuleClientEntry(ctx, AdminClientID, "admin")
		return nil
	}

	bs.log.Info("Admin certificate not found in files, generating new one signed by CA...")

	adminKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate admin key: %w", err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"LCM"},
			OrganizationalUnit: []string{"LCM Admin"},
			CommonName:         AdminClientID,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &adminKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create admin certificate: %w", err)
	}

	adminCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse admin certificate: %w", err)
	}

	if err := bs.saveCertificateToFiles(certDER, adminKey, adminCertPath, adminKeyPath); err != nil {
		return fmt.Errorf("failed to save admin certificate to files: %w", err)
	}

	if err := bs.saveClientCertificateToDatabase(ctx, adminCert, adminKey, serialNumber); err != nil {
		bs.log.Warnf("Failed to save admin certificate to database (non-fatal): %v", err)
	}

	bs.log.Infof("Generated admin certificate with serial number: %d", serialNumber)
	return nil
}

// ensureModuleClientCertificate generates a client certificate for any module using config
func (bs *BootstrapService) ensureModuleClientCertificate(ctx context.Context, caCert *x509.Certificate, caKey any, mod *conf.BootstrapModule) error {
	moduleID := mod.GetModuleId()
	clientID := mod.GetClientId()
	certDir := mod.GetCertDir()
	displayName := mod.GetDisplayName()

	certPath := filepath.Join(bs.config.GetDataDir(), certDir, moduleID+".crt")
	keyPath := filepath.Join(bs.config.GetDataDir(), certDir, moduleID+".key")

	if bs.certificatesExist(certPath, keyPath) {
		bs.log.Infof("%s certificate already exists in files", displayName)
		bs.ensureModuleClientEntry(ctx, clientID, moduleID)
		return nil
	}

	bs.log.Infof("%s certificate not found in files, generating new one signed by CA...", displayName)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate %s key: %w", moduleID, err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
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
		return fmt.Errorf("failed to create %s certificate: %w", moduleID, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse %s certificate: %w", moduleID, err)
	}

	if err := bs.saveCertificateToFiles(certDER, key, certPath, keyPath); err != nil {
		return fmt.Errorf("failed to save %s certificate to files: %w", moduleID, err)
	}

	if err := bs.saveModuleCertificateToDatabase(ctx, cert, key, serialNumber, clientID); err != nil {
		bs.log.Warnf("Failed to save %s certificate to database (non-fatal): %v", moduleID, err)
	}

	bs.log.Infof("Generated %s certificate with serial number: %d", moduleID, serialNumber)
	return nil
}

// ensureModuleServerCertificate generates a server certificate for any module using config
func (bs *BootstrapService) ensureModuleServerCertificate(ctx context.Context, caCert *x509.Certificate, caKey any, mod *conf.BootstrapModule) error {
	moduleID := mod.GetModuleId()
	serverCertDir := mod.GetServerCertDir()
	dnsNames := mod.GetDnsNames()

	serverCertPath := filepath.Join(bs.config.GetDataDir(), serverCertDir, "server.crt")
	serverKeyPath := filepath.Join(bs.config.GetDataDir(), serverCertDir, "server.key")

	if bs.certificatesExist(serverCertPath, serverKeyPath) {
		bs.log.Infof("%s server certificate already exists in files", moduleID)
		return nil
	}

	bs.log.Infof("%s server certificate not found, generating new one...", moduleID)

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate %s server key: %w", moduleID, err)
	}

	serialNumber, err := bs.generateSerialNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

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
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create %s server certificate: %w", moduleID, err)
	}

	if err := bs.saveCertificateToFiles(certDER, serverKey, serverCertPath, serverKeyPath); err != nil {
		return fmt.Errorf("failed to save %s server certificate: %w", moduleID, err)
	}

	bs.log.Infof("Generated %s server certificate with serial number: %d", moduleID, serialNumber)
	return nil
}

// ensureModuleClientEntry ensures the LcmClient entry exists for any module
func (bs *BootstrapService) ensureModuleClientEntry(ctx context.Context, clientID, moduleType string) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, clientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, clientID, map[string]string{
			"type":        moduleType,
			"description": fmt.Sprintf("LCM %s Client (auto-generated)", capitalize(moduleType)),
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for %s (non-fatal): %v", moduleType, err)
		} else {
			bs.log.Infof("Created LcmClient entry for %s", moduleType)
		}
	}
}

// certificatesExist checks if both certificate and key files exist
func (bs *BootstrapService) certificatesExist(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// loadRootCA loads the root CA certificate and private key from files
func (bs *BootstrapService) loadRootCA() (*x509.Certificate, any, error) {
	caCertPath := bs.config.GetCaCertPath()
	caKeyPath := bs.config.GetCaKeyPath()

	if !bs.certificatesExist(caCertPath, caKeyPath) {
		return nil, nil, fmt.Errorf("root CA certificates not found at %s and %s", caCertPath, caKeyPath)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
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

	caKeyPEM, err := os.ReadFile(caKeyPath)
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

// loadCertificateAndKey loads a certificate and RSA private key from files
func (bs *BootstrapService) loadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}

	var key any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key is not an RSA private key")
	}

	return cert, rsaKey, nil
}

// generateSerialNumber generates a unique serial number for certificates
func (bs *BootstrapService) generateSerialNumber(ctx context.Context) (int64, error) {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	for i := 0; i < 100; i++ {
		serialNumber := timestamp + int64(i)
		exists, err := bs.certRepo.IsExistBySerialNumber(ctx, serialNumber)
		if err != nil {
			bs.log.Warnf("Error checking serial number existence: %v", err)
			return timestamp, nil
		}
		if !exists {
			return serialNumber, nil
		}
	}
	return 0, fmt.Errorf("failed to generate unique serial number after 100 attempts")
}

// saveCertificateToFiles saves a certificate and private key to files
func (bs *BootstrapService) saveCertificateToFiles(certDER []byte, key *rsa.PrivateKey, certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	bs.log.Infof("Saved certificate to: %s", certPath)
	bs.log.Infof("Saved private key to: %s", keyPath)

	return nil
}

// saveServerCertificateToDatabase saves the server certificate to the database
func (bs *BootstrapService) saveServerCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)
	dnsNames := cert.DNSNames
	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr("lcm-server"),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(RootCAIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		DnsNames:           dnsNames,
		IpAddresses:        ipAddresses,
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_INTERNAL),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(true),
		PathLenConstraint:  ptr(int32(0)),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	bs.log.Info("Saved server certificate to database")
	return nil
}

// saveClientCertificateToDatabase saves the admin client certificate to the database
func (bs *BootstrapService) saveClientCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(AdminClientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(ServerCertIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	bs.ensureModuleClientEntry(ctx, AdminClientID, "admin")

	bs.log.Info("Saved admin certificate to database")
	return nil
}

// saveModuleCertificateToDatabase saves a module client certificate to the database
func (bs *BootstrapService) saveModuleCertificateToDatabase(ctx context.Context, cert *x509.Certificate, key *rsa.PrivateKey, serialNumber int64, clientID string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fingerprint := sha256.Sum256(cert.Raw)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	keyUsages := bs.keyUsageToStrings(cert.KeyUsage)
	extKeyUsages := bs.extKeyUsageToStrings(cert.ExtKeyUsage)

	certData := &lcmV1.MtlsCertificate{
		SerialNumber:       ptr(serialNumber),
		ClientId:           ptr(clientID),
		CommonName:         ptr(cert.Subject.CommonName),
		SubjectDn:          ptr(cert.Subject.String()),
		IssuerDn:           ptr(cert.Issuer.String()),
		IssuerName:         ptr(RootCAIssuer),
		FingerprintSha256:  ptr(hex.EncodeToString(fingerprint[:])),
		PublicKeyAlgorithm: ptr("RSA"),
		PublicKeySize:      ptr(int32(key.PublicKey.Size() * 8)),
		SignatureAlgorithm: ptr(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptr(string(certPEM)),
		PublicKeyPem:       ptr(string(pubKeyPEM)),
		CertType:           ptr(lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT),
		Status:             ptr(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptr(false),
		KeyUsage:           keyUsages,
		ExtKeyUsage:        extKeyUsages,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}

	_, err = bs.certRepo.Create(ctx, certData)
	if err != nil {
		return fmt.Errorf("failed to create certificate in database: %w", err)
	}

	// Extract module type from clientID (strip "lcm-" prefix)
	moduleType := clientID
	if len(clientID) > 4 && clientID[:4] == "lcm-" {
		moduleType = clientID[4:]
	}
	bs.ensureModuleClientEntry(ctx, clientID, moduleType)

	bs.log.Infof("Saved %s certificate to database", clientID)
	return nil
}

// keyUsageToStrings converts x509.KeyUsage to a slice of strings
func (bs *BootstrapService) keyUsageToStrings(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

// extKeyUsageToStrings converts []x509.ExtKeyUsage to a slice of strings
func (bs *BootstrapService) extKeyUsageToStrings(ekus []x509.ExtKeyUsage) []string {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return usages
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

// ptr is a helper function to create a pointer to a value
func ptr[T any](v T) *T {
	return &v
}
