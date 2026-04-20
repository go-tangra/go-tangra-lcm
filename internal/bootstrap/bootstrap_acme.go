package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/issuedcertificate"
	_ "github.com/go-tangra/go-tangra-lcm/pkg/dns/init" // register DNS providers
	"github.com/go-tangra/go-tangra-lcm/pkg/dns/registry"
)

// acmeBootstrapUser implements the registration.User interface for lego
type acmeBootstrapUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeBootstrapUser) GetEmail() string                 { return u.email }
func (u *acmeBootstrapUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeBootstrapUser) GetPrivateKey() crypto.PrivateKey  { return u.key }

const (
	// FrontendClientID is the client_id for the frontend ACME certificate
	FrontendClientID = "lcm-frontend"

	// FrontendACMEIssuerName is the issuer name for the frontend ACME certificate
	FrontendACMEIssuerName = "lcm-frontend-acme"
)

// ensureFrontendCertificate ensures the frontend ACME certificate exists and is valid.
// This is a non-fatal step - if ACME fails, bootstrap continues.
func (bs *BootstrapService) ensureFrontendCertificate(ctx context.Context) error {
	cfg := bs.config.GetFrontendCertificate()
	if cfg == nil || !cfg.GetEnabled() {
		return nil
	}

	domain := cfg.GetDomain()
	if domain == "" {
		return fmt.Errorf("frontend certificate domain is required")
	}

	outputDir := cfg.GetOutputDir()
	if outputDir == "" {
		outputDir = "frontend"
	}

	certDir := filepath.Join(bs.config.GetDataDir(), outputDir)
	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")

	// Check if certificate already exists and is valid
	if bs.certificatesExist(certPath, keyPath) {
		valid, expiresAt, err := bs.isCertificateValid(certPath, cfg.GetRenewBeforeDays())
		if err != nil {
			bs.log.Warnf("Failed to check frontend certificate validity: %v", err)
		} else if valid {
			bs.log.Infof("Frontend certificate valid until %s", expiresAt.Format(time.RFC3339))
			// Ensure the certificate is registered in the DB even if it was issued before this code
			bs.registerExistingFrontendCertificate(ctx, cfg, certPath, keyPath)
			return nil
		}
		bs.log.Infof("Frontend certificate expires at %s, renewing...", expiresAt.Format(time.RFC3339))
	} else {
		bs.log.Info("Frontend certificate not found, requesting new one...")
	}

	// Issue new certificate via ACME
	certData, err := bs.requestACMECertificate(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to obtain ACME certificate: %w", err)
	}

	// Write certificate files
	if err := bs.writeFrontendCertificateFiles(certDir, certData); err != nil {
		return fmt.Errorf("failed to write frontend certificate files: %w", err)
	}

	// Register the certificate in the database for automatic renewal
	if err := bs.registerFrontendCertificate(ctx, cfg, certData); err != nil {
		bs.log.Warnf("Failed to register frontend certificate in database (non-fatal): %v", err)
	}

	bs.log.Infof("Frontend ACME certificate obtained for %s", domain)
	return nil
}

// isCertificateValid checks if a certificate is valid and not expiring soon.
func (bs *BootstrapService) isCertificateValid(certPath string, renewBeforeDays int32) (bool, time.Time, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if renewBeforeDays <= 0 {
		renewBeforeDays = 30
	}

	renewAt := cert.NotAfter.Add(-time.Duration(renewBeforeDays) * 24 * time.Hour)
	return time.Now().Before(renewAt), cert.NotAfter, nil
}

// acmeCertificateData holds the raw certificate data from ACME
type acmeCertificateData struct {
	Certificate       []byte
	PrivateKey        []byte
	IssuerCertificate []byte
}

// requestACMECertificate requests a certificate from the ACME server via DNS-01.
func (bs *BootstrapService) requestACMECertificate(_ context.Context, cfg interface {
	GetDomain() string
	GetAdditionalNames() []string
	GetAcmeEndpoint() string
	GetAcmeEmail() string
	GetDnsProvider() string
	GetDnsProviderConfig() map[string]string
	GetKeyType() string
	GetKeySize() int32
	GetDnsResolvers() []string
}) (*acmeCertificateData, error) {

	// Generate ACME account key (always EC-256 for account key)
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ACME account key: %w", err)
	}

	// Check for persisted account key
	accountKeyPath := filepath.Join(bs.config.GetDataDir(), "frontend", "acme-account.key")
	if keyData, err := os.ReadFile(accountKeyPath); err == nil {
		block, _ := pem.Decode(keyData)
		if block != nil {
			if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				accountKey = parsed
				bs.log.Info("Loaded existing ACME account key")
			}
		}
	}

	user := &acmeBootstrapUser{
		email: cfg.GetAcmeEmail(),
		key:   accountKey,
	}

	// Configure lego client
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = cfg.GetAcmeEndpoint()

	// Set certificate key type
	keyType := cfg.GetKeyType()
	keySize := cfg.GetKeySize()
	switch keyType {
	case "ec", "ecdsa":
		switch keySize {
		case 384:
			legoConfig.Certificate.KeyType = certcrypto.EC384
		default:
			legoConfig.Certificate.KeyType = certcrypto.EC256
		}
	case "rsa":
		switch keySize {
		case 3072:
			legoConfig.Certificate.KeyType = certcrypto.RSA3072
		case 4096:
			legoConfig.Certificate.KeyType = certcrypto.RSA4096
		default:
			legoConfig.Certificate.KeyType = certcrypto.RSA2048
		}
	default:
		legoConfig.Certificate.KeyType = certcrypto.EC256
	}

	// Create lego client
	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Register ACME account
	bs.log.Infof("Registering ACME account: email=%s, endpoint=%s", cfg.GetAcmeEmail(), cfg.GetAcmeEndpoint())
	reg, err := legoClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register ACME account: %w", err)
	}
	user.registration = reg
	bs.log.Infof("ACME account registered: uri=%s", reg.URI)

	// Persist account key for reuse
	if err := bs.persistACMEAccountKey(accountKeyPath, accountKey); err != nil {
		bs.log.Warnf("Failed to persist ACME account key (non-fatal): %v", err)
	}

	// Configure DNS provider
	providerName := cfg.GetDnsProvider()
	providerConfig := cfg.GetDnsProviderConfig()
	if providerName == "" {
		return nil, fmt.Errorf("dns_provider is required for frontend certificate")
	}

	dnsProvider, err := registry.GetProvider(providerName, providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s': %w", providerName, err)
	}

	// Configure DNS-01 provider with optional custom recursive nameservers
	// Priority: per-frontend config > global LCM config > hardcoded defaults
	resolvers := cfg.GetDnsResolvers()
	if len(resolvers) == 0 && bs.config != nil {
		resolvers = bs.config.GetDnsResolvers()
	}
	if len(resolvers) == 0 {
		resolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	bs.log.Infof("Using DNS resolvers for propagation check: %v", resolvers)

	if err := legoClient.Challenge.SetDNS01Provider(dnsProvider, dns01.AddRecursiveNameservers(resolvers)); err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	// Build domain list
	domains := []string{cfg.GetDomain()}
	for _, san := range cfg.GetAdditionalNames() {
		// Avoid duplicates
		found := false
		for _, d := range domains {
			if d == san {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, san)
		}
	}

	bs.log.Infof("Requesting ACME certificate for domains: %v", domains)

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := legoClient.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	bs.log.Info("ACME certificate obtained successfully")

	return &acmeCertificateData{
		Certificate:       certificates.Certificate,
		PrivateKey:        certificates.PrivateKey,
		IssuerCertificate: certificates.IssuerCertificate,
	}, nil
}

// persistACMEAccountKey saves the ACME account key to disk for reuse across restarts.
func (bs *BootstrapService) persistACMEAccountKey(path string, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0600)
}

// writeFrontendCertificateFiles writes the certificate, key, and CA to disk.
func (bs *BootstrapService) writeFrontendCertificateFiles(certDir string, data *acmeCertificateData) error {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write fullchain certificate
	certPath := filepath.Join(certDir, "server.crt")
	if err := os.WriteFile(certPath, data.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyPath := filepath.Join(certDir, "server.key")
	if err := os.WriteFile(keyPath, data.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write issuer certificate (CA chain)
	if len(data.IssuerCertificate) > 0 {
		caPath := filepath.Join(certDir, "ca.crt")
		if err := os.WriteFile(caPath, data.IssuerCertificate, 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate: %w", err)
		}
	}

	bs.log.Infof("Saved frontend certificate to: %s", certPath)
	bs.log.Infof("Saved frontend private key to: %s", keyPath)

	return nil
}

// ensureFrontendIssuer ensures the ACME issuer record exists for frontend certificate renewal.
func (bs *BootstrapService) ensureFrontendIssuer(ctx context.Context, cfg interface {
	GetAcmeEmail() string
	GetAcmeEndpoint() string
	GetDnsProvider() string
	GetDnsProviderConfig() map[string]string
	GetKeyType() string
	GetKeySize() int32
}) (*ent.Issuer, error) {
	existing, err := bs.issuerRepo.GetByTenantAndName(ctx, 0, FrontendACMEIssuerName)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing issuer: %w", err)
	}
	if existing != nil {
		return existing, nil
	}

	req := &lcmV1.CreateIssuerRequest{
		Name:    FrontendACMEIssuerName,
		Type:    "acme",
		KeyType: cfg.GetKeyType(),
		Description: "Auto-generated ACME issuer for frontend certificate renewal",
		AcmeIssuer: &lcmV1.AcmeIssuer{
			Email:          cfg.GetAcmeEmail(),
			Endpoint:       cfg.GetAcmeEndpoint(),
			KeyType:        cfg.GetKeyType(),
			KeySize:        cfg.GetKeySize(),
			ChallengeType:  lcmV1.ChallengeType_DNS,
			ProviderName:   cfg.GetDnsProvider(),
			ProviderConfig: cfg.GetDnsProviderConfig(),
		},
		Status: lcmV1.IssuerStatus_ISSUER_STATUS_ACTIVE,
	}

	issuerEntity, err := bs.issuerRepo.Create(ctx, 0, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create frontend ACME issuer: %w", err)
	}

	bs.log.Info("Created ACME issuer 'lcm-frontend-acme'")
	return issuerEntity, nil
}

// registerFrontendCertificate registers a newly-issued frontend certificate in the database
// so the renewal scheduler can track and renew it automatically.
func (bs *BootstrapService) registerFrontendCertificate(ctx context.Context, cfg interface {
	GetDomain() string
	GetAdditionalNames() []string
	GetKeyType() string
	GetKeySize() int32
	GetRenewBeforeDays() int32
}, certData *acmeCertificateData) error {
	// Ensure the ACME issuer exists
	if _, err := bs.ensureFrontendIssuer(ctx, bs.config.GetFrontendCertificate()); err != nil {
		return fmt.Errorf("failed to ensure frontend issuer: %w", err)
	}

	domain := cfg.GetDomain()
	certID := "frontend-acme-" + domain

	// Build domain list
	domains := []string{domain}
	for _, san := range cfg.GetAdditionalNames() {
		found := false
		for _, d := range domains {
			if d == san {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, san)
		}
	}

	// Parse the issued cert once and derive expiry + actual key info from its SPKI.
	issuedCert, err := parseLeafCert(certData.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}
	expiresAt := issuedCert.NotAfter
	actualKeyType, actualKeySize := extractSPKIInfo(issuedCert)

	renewBeforeDays := cfg.GetRenewBeforeDays()
	if renewBeforeDays <= 0 {
		renewBeforeDays = 30
	}

	keyTypeEnum := mapKeyType(actualKeyType)

	// Check if record already exists
	existing, err := bs.issuedCertRepo.GetByID(ctx, certID)
	if err != nil {
		return fmt.Errorf("failed to check existing certificate record: %w", err)
	}

	if existing != nil {
		// Update the existing record with new cert data
		err = bs.issuedCertRepo.UpdateCertificate(ctx, certID,
			string(certData.Certificate),
			string(certData.PrivateKey),
			string(certData.IssuerCertificate),
			"",
			expiresAt,
			actualKeyType,
			actualKeySize,
		)
		if err != nil {
			return fmt.Errorf("failed to update certificate record: %w", err)
		}
		bs.log.Info("Updated frontend certificate in database")
	} else {
		// Create a new record
		cert := &ent.IssuedCertificate{
			ID:                        certID,
			IssuerName:                FrontendACMEIssuerName,
			IssuerType:                "acme",
			CommonName:                domain,
			Domains:                   domains,
			CertPem:                   string(certData.Certificate),
			PrivateKeyPem:             string(certData.PrivateKey),
			CaCertPem:                 string(certData.IssuerCertificate),
			ExpiresAt:                 expiresAt,
			Status:                    issuedcertificate.StatusIssued,
			AutoRenewEnabled:          true,
			AutoRenewDaysBeforeExpiry: renewBeforeDays,
			ServerGeneratedKey:        true,
			KeyType:                   keyTypeEnum,
			KeySize:                   actualKeySize,
		}

		if _, err := bs.issuedCertRepo.Create(ctx, cert); err != nil {
			return fmt.Errorf("failed to create certificate record: %w", err)
		}
		bs.log.Info("Registered frontend certificate in database")
	}

	// Ensure LcmClient entry exists for the frontend
	bs.ensureFrontendClientEntry(ctx)

	return nil
}

// registerExistingFrontendCertificate registers an existing on-disk frontend certificate
// in the database if it isn't already tracked. This ensures the renewal scheduler picks
// up certificates that were issued before this code was deployed.
func (bs *BootstrapService) registerExistingFrontendCertificate(ctx context.Context, cfg interface {
	GetDomain() string
	GetAdditionalNames() []string
	GetKeyType() string
	GetKeySize() int32
	GetRenewBeforeDays() int32
}, certPath, keyPath string) {
	domain := cfg.GetDomain()
	certID := "frontend-acme-" + domain

	// Check if already registered
	existing, err := bs.issuedCertRepo.GetByID(ctx, certID)
	if err != nil {
		bs.log.Warnf("Failed to check frontend certificate DB record (non-fatal): %v", err)
		return
	}
	if existing != nil {
		return // Already registered
	}

	// Read cert and key from disk
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		bs.log.Warnf("Failed to read frontend cert for DB registration (non-fatal): %v", err)
		return
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		bs.log.Warnf("Failed to read frontend key for DB registration (non-fatal): %v", err)
		return
	}

	// Read CA cert if it exists
	caPath := filepath.Join(filepath.Dir(certPath), "ca.crt")
	caPEM, _ := os.ReadFile(caPath)

	certData := &acmeCertificateData{
		Certificate:       certPEM,
		PrivateKey:        keyPEM,
		IssuerCertificate: caPEM,
	}

	if err := bs.registerFrontendCertificate(ctx, cfg, certData); err != nil {
		bs.log.Warnf("Failed to register existing frontend certificate in DB (non-fatal): %v", err)
	}
}

// ensureFrontendClientEntry ensures the LcmClient entry exists for the frontend
func (bs *BootstrapService) ensureFrontendClientEntry(ctx context.Context) {
	existingClient, _ := bs.clientRepo.GetByTenantAndClientID(ctx, 0, FrontendClientID)
	if existingClient == nil {
		_, err := bs.clientRepo.Create(ctx, 0, FrontendClientID, map[string]string{
			"type":        "frontend",
			"description": "LCM Frontend Certificate (auto-generated)",
		})
		if err != nil {
			bs.log.Warnf("Failed to create LcmClient entry for frontend (non-fatal): %v", err)
		} else {
			bs.log.Info("Created LcmClient entry for frontend")
		}
	}
}

// parseLeafCert parses the leaf (first) PEM-encoded certificate.
func parseLeafCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// extractSPKIInfo returns the public-key algorithm ("rsa"/"ecdsa"/"ed25519")
// and key size in bits for the given certificate's SubjectPublicKeyInfo.
func extractSPKIInfo(cert *x509.Certificate) (string, int32) {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "rsa", int32(pk.N.BitLen())
	case *ecdsa.PublicKey:
		return "ecdsa", int32(pk.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "ed25519", 256
	default:
		return "", 0
	}
}

// mapKeyType maps config key type strings to the ent KeyType enum.
func mapKeyType(kt string) issuedcertificate.KeyType {
	switch strings.ToLower(kt) {
	case "rsa":
		return issuedcertificate.KeyTypeRsa
	case "ec", "ecdsa":
		return issuedcertificate.KeyTypeEcdsa
	default:
		return issuedcertificate.KeyTypeEcdsa
	}
}

// Ensure crypto import is used
var _ crypto.PrivateKey
