package bootstrap

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

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

	if err := legoClient.Challenge.SetDNS01Provider(dnsProvider); err != nil {
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

// Ensure crypto import is used
var _ crypto.PrivateKey
