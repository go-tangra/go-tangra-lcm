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
	"strconv"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
	appViewer "github.com/go-tangra/go-tangra-common/viewer"
	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
	"github.com/go-tangra/go-tangra-lcm/internal/conf"
	"github.com/go-tangra/go-tangra-lcm/internal/data"
)

// signCertRateLimit is the per-module-id token-bucket rate. 10 mints
// per hour is well above the 30-day renewal cadence (≈12/year) and
// low enough that an attacker burning the secret can't mint a flood.
//
// Burst capacity = 5 covers a single fresh-boot cert.Ensure() call
// (which mints both a server AND a client cert back-to-back) plus a
// few crash/restart cycles before throttling kicks in. With burst=1
// the second cert in a single boot would be denied because the
// bucket was emptied on the first.
const (
	signCertRatePerSec = 10.0 / 3600.0 // 10 / hour
	signCertRateBurst  = 5
)

// signCertMaxLifetime caps the issued cert lifetime regardless of
// what the client requested. Matches the existing CA cert validity
// (1 year) — re-issuance happens through cert.Ensure() at the 30-day
// renewal mark.
const signCertMaxLifetime = 365 * 24 * time.Hour

// SignCertificateService is the canonical implementation of
// LcmBootstrapServiceServer. It owns the new CSR-based RPCs
// (SignModuleCertificate + GetCABundle) and forwards the legacy
// BootstrapCertificates RPC to the original BootstrapService so the
// pre-rework lcm-init flow keeps working until every module has
// migrated. After migration, the legacy RPC + BootstrapService go
// away entirely and this struct stays.
type SignCertificateService struct {
	commonV1.UnimplementedLcmBootstrapServiceServer

	config     *conf.LCM
	certRepo   *data.MtlsCertificateRepo
	clientRepo *data.LcmClientRepo
	legacy     *BootstrapService
	log        *log.Helper

	// Per-module-id rate limiter. Modules are bounded in number
	// (typically <30 in production), so a plain sync.Map is fine —
	// no LRU needed.
	rateMu       sync.Mutex
	rateBuckets  map[string]*rate.Limiter
	cachedCABytes []byte
	cachedCAFp    string
	caLoadOnce    sync.Once
	caLoadErr     error
}

// NewSignCertificateService is the Wire constructor. It takes the
// existing BootstrapService as a dep so the deprecated
// BootstrapCertificates RPC keeps responding to lcm-init during the
// migration window.
func NewSignCertificateService(
	ctx *bootstrap.Context,
	config *conf.LCM,
	certRepo *data.MtlsCertificateRepo,
	clientRepo *data.LcmClientRepo,
	legacy *BootstrapService,
) *SignCertificateService {
	return &SignCertificateService{
		config:      config,
		certRepo:    certRepo,
		clientRepo:  clientRepo,
		legacy:      legacy,
		log:         ctx.NewLoggerHelper("lcm/sign-certificate-service"),
		rateBuckets: make(map[string]*rate.Limiter),
	}
}

// BootstrapCertificates is a thin pass-through to the deprecated
// BootstrapService so callers of the old key-on-server flow keep
// working during the rework migration. Remove this method (and the
// `legacy` field) once every module is on SignModuleCertificate.
func (s *SignCertificateService) BootstrapCertificates(
	ctx context.Context,
	req *commonV1.BootstrapCertificatesRequest,
) (*commonV1.BootstrapCertificatesResponse, error) {
	return s.legacy.BootstrapCertificates(ctx, req)
}

// SignModuleCertificate validates the shared secret, throttles the
// caller, parses the CSR, and signs it with the LCM root CA. The
// private key never crosses the wire — the CSR carries only the
// public key.
func (s *SignCertificateService) SignModuleCertificate(
	ctx context.Context,
	req *commonV1.SignModuleCertificateRequest,
) (*commonV1.SignModuleCertificateResponse, error) {
	if req.GetSecret() != s.config.GetModuleRegistrationSecret() {
		// Non-leaking error: the caller is unauthenticated, no need
		// to distinguish between "wrong secret" and "no secret set".
		return nil, status.Errorf(codes.Unauthenticated, "invalid module bootstrap secret")
	}
	moduleID := req.GetModuleId()
	if moduleID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "module_id is required")
	}
	if req.GetCsrPem() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "csr_pem is required")
	}
	if req.GetKind() == commonV1.CertificateKind_CERTIFICATE_KIND_UNSPECIFIED {
		return nil, status.Errorf(codes.InvalidArgument, "kind is required")
	}

	if !s.allow(moduleID) {
		return nil, status.Errorf(codes.ResourceExhausted,
			"sign rate exceeded for module %q (limit: 10/hour)", moduleID)
	}

	csr, err := parseSignCSR(req.GetCsrPem())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "csr signature invalid: %v", err)
	}

	ctx = appViewer.NewSystemViewerContext(ctx)

	caCert, caKey, err := s.loadRootCA()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load root CA: %v", err)
	}
	caPEM, caFp, err := s.cachedCA()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load CA bundle: %v", err)
	}

	lifetime := signCertMaxLifetime
	if req.LifetimeDays != nil && *req.LifetimeDays > 0 {
		requested := time.Duration(*req.LifetimeDays) * 24 * time.Hour
		if requested < lifetime {
			lifetime = requested
		}
	}

	now := time.Now()
	serial, err := s.allocSerial(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "alloc serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         csr.Subject.CommonName,
			Organization:       []string{"tangra"},
			OrganizationalUnit: []string{moduleID},
		},
		NotBefore:             now,
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
		// Echo the CSR's SANs verbatim — the module asked for them.
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
	}

	switch req.GetKind() {
	case commonV1.CertificateKind_CERTIFICATE_KIND_SERVER:
		// Server certs also get clientAuth so the module can dial its
		// peers with the same cert it serves on. Matches the existing
		// generateServerCert path in bootstrap_service.go.
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	case commonV1.CertificateKind_CERTIFICATE_KIND_CLIENT:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown CertificateKind %v", req.GetKind())
	}

	// Loopback always gets added so the cert validates for in-pod
	// health checks regardless of what the module requested.
	tmpl.IPAddresses = appendLoopback(tmpl.IPAddresses)

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign csr: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Persist for audit / revocation. Failure here is non-fatal — the
	// module already has the cert bytes; the worst case is the audit
	// row is missing, which a follow-up reconcile can backfill.
	if cert, perr := x509.ParseCertificate(certDER); perr == nil {
		s.persistAudit(ctx, cert, moduleID, csr.Subject.CommonName, serial, req.GetKind())
	}

	s.log.Infof("signed %s cert for %s (cn=%s, serial=%d, lifetime=%s)",
		kindSlug(req.GetKind()), moduleID, csr.Subject.CommonName, serial, lifetime)

	return &commonV1.SignModuleCertificateResponse{
		CertificatePem:       string(certPEM),
		CaCertificatePem:     string(caPEM),
		CaFingerprintSha256:  caFp,
		NotBefore:            timestamppb.New(now),
		NotAfter:             timestamppb.New(now.Add(lifetime)),
		SerialNumber:         strconv.FormatInt(serial, 10),
	}, nil
}

// GetCABundle returns the platform CA so callers can pin its
// fingerprint. No auth required — the CA cert is already public by
// construction (every TLS client in the stack will see it).
func (s *SignCertificateService) GetCABundle(
	_ context.Context,
	_ *commonV1.GetCABundleRequest,
) (*commonV1.GetCABundleResponse, error) {
	pemBytes, fp, err := s.cachedCA()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load CA: %v", err)
	}
	return &commonV1.GetCABundleResponse{
		CaCertificatePem:    string(pemBytes),
		CaFingerprintSha256: fp,
	}, nil
}

// allow returns true when the bucket for moduleID has a token. New
// buckets are created on first sight; the burst is 1 so a legit boot
// never sees a delay, and the token refill is 10/hour.
func (s *SignCertificateService) allow(moduleID string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	bucket, ok := s.rateBuckets[moduleID]
	if !ok {
		bucket = rate.NewLimiter(rate.Limit(signCertRatePerSec), signCertRateBurst)
		s.rateBuckets[moduleID] = bucket
	}
	return bucket.Allow()
}

// cachedCA loads + memoizes the CA cert PEM and its SHA-256
// fingerprint. The CA is stable for the process lifetime; reading it
// from disk per RPC would be wasted I/O.
func (s *SignCertificateService) cachedCA() ([]byte, string, error) {
	s.caLoadOnce.Do(func() {
		raw, err := os.ReadFile(s.config.GetCaCertPath())
		if err != nil {
			s.caLoadErr = fmt.Errorf("read CA: %w", err)
			return
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			s.caLoadErr = fmt.Errorf("CA file is not a CERTIFICATE PEM block")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			s.caLoadErr = fmt.Errorf("parse CA: %w", err)
			return
		}
		sum := sha256.Sum256(cert.Raw)
		s.cachedCABytes = raw
		s.cachedCAFp = hex.EncodeToString(sum[:])
	})
	return s.cachedCABytes, s.cachedCAFp, s.caLoadErr
}

// loadRootCA returns the parsed CA cert + its private key, ready to
// sign with. Same logic as bootstrap_service.go's loadRootCA — kept
// duplicated here to avoid coupling the new service to the legacy
// one, which is going away.
func (s *SignCertificateService) loadRootCA() (*x509.Certificate, any, error) {
	caCertPEM, err := os.ReadFile(s.config.GetCaCertPath())
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(s.config.GetCaKeyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("decode CA key PEM")
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
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	return caCert, caKey, nil
}

func (s *SignCertificateService) allocSerial(ctx context.Context) (int64, error) {
	base := time.Now().UnixNano() / int64(time.Millisecond)
	for i := 0; i < 100; i++ {
		serial := base + int64(i)
		exists, err := s.certRepo.IsExistBySerialNumber(ctx, serial)
		if err != nil {
			return base, nil // best-effort; collisions are vanishingly rare on millis
		}
		if !exists {
			return serial, nil
		}
	}
	return 0, fmt.Errorf("no unique serial in 100 attempts")
}

// persistAudit writes the issued cert into the mtls_certificate table
// and ensures an LcmClient row exists for client-kind certs. Failures
// are logged but not surfaced — losing the audit row should never
// stop a module from booting.
func (s *SignCertificateService) persistAudit(
	ctx context.Context,
	cert *x509.Certificate,
	moduleID, commonName string,
	serial int64,
	kind commonV1.CertificateKind,
) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		s.log.Warnf("marshal pub key: %v", err)
		return
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fp := sha256.Sum256(cert.Raw)

	pubKeySize := int32(0)
	if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		pubKeySize = int32(rsaPub.Size() * 8)
	}

	dbKind := lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_INTERNAL
	if kind == commonV1.CertificateKind_CERTIFICATE_KIND_CLIENT {
		dbKind = lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT
	}

	row := &lcmV1.MtlsCertificate{
		SerialNumber:       ptrInt64(serial),
		ClientId:           ptrString(commonName),
		CommonName:         ptrString(cert.Subject.CommonName),
		SubjectDn:          ptrString(cert.Subject.String()),
		IssuerDn:           ptrString(cert.Issuer.String()),
		IssuerName:         ptrString("lcm-root-ca"),
		FingerprintSha256:  ptrString(hex.EncodeToString(fp[:])),
		PublicKeyAlgorithm: ptrString("RSA"),
		PublicKeySize:      &pubKeySize,
		SignatureAlgorithm: ptrString(cert.SignatureAlgorithm.String()),
		CertificatePem:     ptrString(string(certPEM)),
		PublicKeyPem:       ptrString(string(pubKeyPEM)),
		CertType:           &dbKind,
		Status:             ptrCertStatus(lcmV1.MtlsCertificateStatus_MTLS_CERTIFICATE_STATUS_ACTIVE),
		IsCa:               ptrBool(false),
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		IssuedAt:           timestamppb.Now(),
	}
	if _, err := s.certRepo.Create(ctx, row); err != nil {
		s.log.Warnf("persist cert audit row failed (non-fatal): %v", err)
	}

	if kind == commonV1.CertificateKind_CERTIFICATE_KIND_CLIENT {
		// Ensure a client row exists so the cert renewal scheduler can
		// find it. Existing rows are left alone.
		if existing, _ := s.clientRepo.GetByTenantAndClientID(ctx, 0, commonName); existing == nil {
			if _, err := s.clientRepo.Create(ctx, 0, commonName, map[string]string{
				"type":        moduleID,
				"description": fmt.Sprintf("LCM %s client (auto-created via SignModuleCertificate)", moduleID),
			}); err != nil {
				s.log.Warnf("create LcmClient row failed (non-fatal): %v", err)
			}
		}
	}
}

// helpers — small typed pointer constructors avoid `&v` literal noise
// in the populated proto rows above.

func ptrString(v string) *string                                { return &v }
func ptrInt64(v int64) *int64                                   { return &v }
func ptrBool(v bool) *bool                                      { return &v }
func ptrCertStatus(v lcmV1.MtlsCertificateStatus) *lcmV1.MtlsCertificateStatus {
	return &v
}

func parseSignCSR(pemStr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected CERTIFICATE REQUEST, got %q", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func appendLoopback(in []net.IP) []net.IP {
	v4 := net.IPv4(127, 0, 0, 1)
	v6 := net.IPv6loopback
	have4, have6 := false, false
	for _, ip := range in {
		if ip.Equal(v4) {
			have4 = true
		}
		if ip.Equal(v6) {
			have6 = true
		}
	}
	if !have4 {
		in = append(in, v4)
	}
	if !have6 {
		in = append(in, v6)
	}
	return in
}

func kindSlug(k commonV1.CertificateKind) string {
	switch k {
	case commonV1.CertificateKind_CERTIFICATE_KIND_SERVER:
		return "server"
	case commonV1.CertificateKind_CERTIFICATE_KIND_CLIENT:
		return "client"
	default:
		return "unknown"
	}
}
