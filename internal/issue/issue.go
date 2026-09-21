// Package issue is the certificate-authority service layer of lcm: it owns
// issuers (their sealed ACME/DNS credentials), mints SPIFFE leaf certificates
// from a self-signed CA, and runs the certificate lifecycle (renew, revoke,
// download). Every entry point is authorised (SR-002: the caller must be
// entitled to the SPIFFE identity), audited, and never returns key material
// beyond the one-time delivery of a generated private key at issuance.
package issue

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/audit"
	"github.com/go-freya/freya/services/lcm/internal/authz"
	"github.com/go-freya/freya/services/lcm/internal/ca"
	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/repo"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// Validity bounds (seconds). A request of 0 uses the default; anything else is
// clamped to [MinValiditySeconds, MaxValiditySeconds] (the issuer ceiling).
const (
	MinValiditySeconds     = 60
	DefaultValiditySeconds = 90 * 24 * 3600
	MaxValiditySeconds     = 365 * 24 * 3600
)

// expiringWindow is the fixed side of the expiring window; the effective window
// is min(expiringWindow, 0.5*TTL).
const expiringWindow = 30 * 24 * time.Hour

// issuerSecretFields are the issuer settings redacted on every read.
var issuerSecretFields = []string{"acme_account_key", "dns_credential", "eab_hmac_key"}

// ValidationError is a client-safe rejection carrying the offending field.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return "issue: " + e.Field + ": " + e.Message
	}
	return "issue: " + e.Message
}

func invalid(field, msg string) error { return &ValidationError{Field: field, Message: msg} }

// InUseError refuses a deletion while referencing resources exist.
type InUseError struct {
	What  string
	Count int
}

func (e *InUseError) Error() string {
	return fmt.Sprintf("issue: %d %s reference it", e.Count, e.What)
}

// Service is the issuer/issuance/lifecycle service.
type Service struct {
	st    repo.Store
	ca    *ca.Authority
	env   *sealed.Envelope
	az    *authz.Authorizer
	audit *audit.Writer
	now   func() time.Time
}

// New wires the service. clock defaults to time.Now when nil.
func New(st repo.Store, authority *ca.Authority, env *sealed.Envelope, az *authz.Authorizer, aw *audit.Writer, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{st: st, ca: authority, env: env, az: az, audit: aw, now: clock}
}

// SetClock injects the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// IssueInput is a signing request. Exactly one of CSRPEM (sign the request's
// public key) or an empty CSR (generate a keypair) applies.
type IssueInput struct {
	IssuerID        string
	SpiffeID        string
	CSRPEM          string
	Subject         string
	DNSSans         []string
	ValiditySeconds int64
	DeliverKey      bool
	// RetainKey keeps a module-generated key sealed for later download instead
	// of clearing it after one-time delivery (used by the async issue path,
	// where the key cannot be returned inline).
	RetainKey       bool
}

// Bundle is the result of issuance or download. KeyPEM is populated only once,
// at issuance of a module-generated key; it is empty everywhere else.
type Bundle struct {
	Certificate CertificateView
	CertPEM     string
	ChainPEM    string
	BundlePEM   string
	KeyPEM      string
}

// userPtr returns the caller's user id as a pointer, or nil for a service.
func userPtr(s authz.Subjects) *string {
	if s.UserID == "" {
		return nil
	}
	u := s.UserID
	return &u
}

func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// emit records an audit event best-effort.
func (s *Service) emit(ctx context.Context, e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Record(ctx, e)
	}
}

// resolveIssuer resolves the issuer (given, else the default for the SPIFFE id's
// trust domain) and the parsed SPIFFE id, enforcing the trust-domain match.
func (s *Service) resolveIssuer(ctx context.Context, subj authz.Subjects, in IssueInput) (store.Issuer, csr.SPIFFEID, error) {
	sid, err := csr.ParseSPIFFEID(in.SpiffeID)
	if err != nil {
		return store.Issuer{}, csr.SPIFFEID{}, invalid("spiffe_id", "invalid SPIFFE ID")
	}
	var issuer store.Issuer
	if in.IssuerID != "" {
		issuer, err = s.st.GetIssuer(ctx, subj.TenantID, in.IssuerID)
	} else {
		issuer, err = s.st.DefaultIssuer(ctx, subj.TenantID, sid.TrustDomain)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.Issuer{}, csr.SPIFFEID{}, invalid("issuer_id", "issuer not found")
		}
		return store.Issuer{}, csr.SPIFFEID{}, err
	}
	if issuer.TrustDomain != sid.TrustDomain {
		return store.Issuer{}, csr.SPIFFEID{}, invalid("spiffe_id", "trust domain does not match the issuer")
	}
	return issuer, sid, nil
}

// entitled enforces SR-002: the caller is entitled to the SPIFFE id when they
// hold Use on the issuer, or (a service caller) the SPIFFE id is their own
// identity. Request-supplied secrets are never trusted; there are none.
func (s *Service) entitled(ctx context.Context, subj authz.Subjects, issuer store.Issuer, sid csr.SPIFFEID) error {
	err := s.az.Check(ctx, subj, authz.Issuer, issuer.ID, authz.Use)
	if err == nil {
		return nil
	}
	if !errors.Is(err, authz.ErrForbidden) && !errors.Is(err, authz.ErrNotFound) {
		return err
	}
	if subj.Service != "" {
		if own, perr := csr.ParseSPIFFEID(subj.Service); perr == nil {
			if own.TrustDomain == sid.TrustDomain && own.Path == sid.Path {
				return nil
			}
		}
	}
	return authz.ErrForbidden
}

// clampValidity applies the [Min,Max] bounds, defaulting a non-positive request.
func clampValidity(seconds int64) time.Duration {
	if seconds <= 0 {
		seconds = DefaultValiditySeconds
	}
	if seconds < MinValiditySeconds {
		seconds = MinValiditySeconds
	}
	if seconds > MaxValiditySeconds {
		seconds = MaxValiditySeconds
	}
	return time.Duration(seconds) * time.Second
}

// mintReq carries the resolved inputs of a single signing operation.
type mintReq struct {
	subject         string
	csrPEM          string
	dnsSans         []string
	validitySeconds int64
	deliverKey      bool
	retainKey       bool
	event           audit.EventType
	logEvent        string
}

// mint performs the signing, persistence and audit for an entitled request. The
// entitlement and trust-domain checks are the caller's responsibility.
func (s *Service) mint(ctx context.Context, subj authz.Subjects, issuer store.Issuer, sid csr.SPIFFEID, req mintReq) (Bundle, error) {
	if issuer.Type != "self_signed" || issuer.CAID == nil {
		return Bundle{}, invalid("issuer_id", "issuer cannot sign certificates")
	}
	caRow, err := s.st.GetCA(ctx, subj.TenantID, *issuer.CAID)
	if err != nil {
		return Bundle{}, err
	}
	signer, caCert, err := s.ca.Signer(ctx, caRow)
	if err != nil {
		return Bundle{}, err
	}

	certID := store.NewID()
	var pub crypto.PublicKey
	var keyPEM string
	var keySealed []byte
	if req.csrPEM != "" {
		parsed, perr := csr.ParseCSR([]byte(req.csrPEM))
		if perr != nil {
			return Bundle{}, invalid("csr", "certificate request rejected")
		}
		if verr := csr.ValidateSANs(req.dnsSans, parsed.DNSNames); verr != nil {
			return Bundle{}, invalid("dns_sans", "CSR SANs are not authorised")
		}
		pub = parsed.CSR.PublicKey
	} else {
		priv, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return Bundle{}, gerr
		}
		pub = &priv.PublicKey
		keyDER, merr := x509.MarshalPKCS8PrivateKey(priv)
		if merr != nil {
			return Bundle{}, merr
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if keySealed, err = s.env.Seal(pemKey, sealed.ADCertKey(certID)); err != nil {
			return Bundle{}, err
		}
		if req.deliverKey {
			keyPEM = string(pemKey)
		}
	}

	now := s.now()
	notAfter := now.Add(clampValidity(req.validitySeconds))
	serial, err := randomSerial()
	if err != nil {
		return Bundle{}, err
	}
	uri, err := url.Parse(sid.String())
	if err != nil {
		return Bundle{}, invalid("spiffe_id", "invalid SPIFFE ID")
	}
	cn := req.subject
	if cn == "" {
		cn = sid.String()
	}
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
		DNSNames:              req.dnsSans,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, pub, signer)
	if err != nil {
		return Bundle{}, err
	}
	certPEM := string(csr.EncodeCertPEM(der))
	bundlePEM, err := s.ca.Bundle(ctx, subj.TenantID, sid.TrustDomain)
	if err != nil {
		return Bundle{}, err
	}
	sansJSON, err := json.Marshal(sansList(req.dnsSans))
	if err != nil {
		return Bundle{}, err
	}

	row := store.IssuedCertificate{
		ID:                certID,
		TenantID:          subj.TenantID,
		IssuerID:          issuer.ID,
		Serial:            serial.String(),
		SpiffeID:          sid.String(),
		Subject:           cn,
		SANs:              sansJSON,
		NotBefore:         now,
		NotAfter:          notAfter,
		FingerprintSHA256: csr.Fingerprint(der),
		Status:            "active",
		CertPEM:           certPEM,
		ChainPEM:          caRow.CertPEM,
		KeySealed:         keySealed,
		AutoRenew:         true,
		Owner:             subj.ActorID(),
		CreatedBy:         userPtr(subj),
		UpdatedBy:         userPtr(subj),
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if ierr := tx.InsertCertificate(ctx, row); ierr != nil {
			return ierr
		}
		if lerr := tx.InsertCertLog(ctx, []store.CertLogRow{{
			TS: now, TenantID: subj.TenantID, CertificateID: certID, Event: req.logEvent, IssuerID: issuer.ID, SpiffeID: sid.String(),
		}}); lerr != nil {
			return lerr
		}
		return authz.New(tx).GrantOwner(ctx, subj.TenantID, authz.Certificate, certID, subj.UserID)
	})
	if err != nil {
		return Bundle{}, err
	}

	s.emit(ctx, audit.Event{
		TenantID: subj.TenantID, EventType: req.event, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"spiffe_id": sid.String(), "issuer_id": issuer.ID, "serial": row.Serial},
	})

	if keyPEM != "" && !req.retainKey {
		// Deliver the generated key exactly once: record delivery so no later
		// call can return it. When retainKey is set (async issuance), the sealed
		// key is kept so the operator can download it afterwards.
		if err := s.st.MarkKeyDelivered(ctx, subj.TenantID, certID); err != nil {
			return Bundle{}, err
		}
		row.KeyDelivered = true
		row.KeySealed = nil
	}

	perms, _, _, _ := s.az.Effective(ctx, subj, authz.Certificate, certID)
	return Bundle{
		Certificate: s.certView(row, perms),
		CertPEM:     certPEM,
		ChainPEM:    caRow.CertPEM,
		BundlePEM:   bundlePEM,
		KeyPEM:      keyPEM,
	}, nil
}

// Issue resolves the issuer, enforces entitlement (SR-002) and mints a leaf.
// PrecheckIssue validates synchronously that the issuer resolves and the caller
// is entitled to the requested SPIFFE identity, so an async caller can return a
// fast 400/403 before backgrounding the mint. It performs no network calls.
func (s *Service) PrecheckIssue(ctx context.Context, subj authz.Subjects, in IssueInput) error {
	issuer, sid, err := s.resolveIssuer(ctx, subj, in)
	if err != nil {
		return err
	}
	return s.entitled(ctx, subj, issuer, sid)
}

func (s *Service) Issue(ctx context.Context, subj authz.Subjects, in IssueInput) (Bundle, error) {
	issuer, sid, err := s.resolveIssuer(ctx, subj, in)
	if err != nil {
		return Bundle{}, err
	}
	if err := s.entitled(ctx, subj, issuer, sid); err != nil {
		return Bundle{}, err
	}
	return s.mint(ctx, subj, issuer, sid, mintReq{
		subject: in.Subject, csrPEM: in.CSRPEM, dnsSans: in.DNSSans, validitySeconds: in.ValiditySeconds,
		deliverKey: in.DeliverKey, retainKey: in.RetainKey, event: audit.CertificateIssued, logEvent: "issued",
	})
}

// sansList normalises a possibly-nil slice to a non-nil slice for JSON.
func sansList(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// randomSerial returns a positive 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
