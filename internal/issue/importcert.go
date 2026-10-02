package issue

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/audit"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// MaxImportPEMBytes bounds each PEM input of an import (certificate with its
// chain, extra chain, private key).
const MaxImportPEMBytes = 64 << 10

// maxImportChain bounds the intermediates kept with an imported certificate.
const maxImportChain = 10

// ImportInput is a certificate (+ chain) and its private key issued by an ACME
// CA outside lcm (e.g. certbot's fullchain.pem and privkey.pem).
type ImportInput struct {
	IssuerID  string
	CertPEM   string // leaf first, optionally followed by the chain
	ChainPEM  string // optional extra chain (certbot chain.pem)
	KeyPEM    string // PKCS#8, PKCS#1 RSA or SEC1 EC; never encrypted
	AutoRenew bool
}

// ImportACME records an externally issued ACME certificate and its key as a
// generic certificate of an ACME issuer, so lcm renews it like one it issued
// itself: renewal re-runs an ACME order for the certificate's DNS names through
// the issuer's account and DNS provider and keeps the imported key. The key is
// stored sealed as PKCS#8 (the format renewal and key download read).
func (s *Service) ImportACME(ctx context.Context, subj authz.Subjects, in ImportInput) (CertificateView, error) {
	if err := s.PrecheckACME(ctx, subj, in.IssuerID); err != nil {
		return CertificateView{}, err
	}
	leaf, chain, err := parseImportCerts(in.CertPEM, in.ChainPEM)
	if err != nil {
		return CertificateView{}, err
	}
	domains, err := importDomains(leaf)
	if err != nil {
		return CertificateView{}, err
	}
	keyPKCS8, err := parseImportKey(in.KeyPEM, leaf)
	if err != nil {
		return CertificateView{}, err
	}

	certID := store.NewID()
	keySealed, err := s.env.Seal(keyPKCS8, sealed.ADCertKey(certID))
	if err != nil {
		return CertificateView{}, err
	}
	sansJSON, _ := json.Marshal(domains)
	row := store.IssuedCertificate{
		ID: certID, TenantID: subj.TenantID, IssuerID: in.IssuerID, Kind: "generic",
		Serial: leaf.SerialNumber.String(), Subject: domains[0], SANs: sansJSON,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, FingerprintSHA256: csr.Fingerprint(leaf.Raw),
		Status: "active", CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), ChainPEM: chain,
		KeySealed: keySealed, AutoRenew: in.AutoRenew,
		Owner: subj.ActorID(), CreatedBy: userPtr(subj), UpdatedBy: userPtr(subj),
	}
	err = s.st.Atomic(ctx, subj.TenantID, func(tx repo.Store) error {
		if ierr := tx.InsertCertificate(ctx, row); ierr != nil {
			return ierr
		}
		if lerr := tx.InsertCertLog(ctx, []store.CertLogRow{{TS: s.now(), TenantID: subj.TenantID, CertificateID: certID, Event: "issued", IssuerID: in.IssuerID, SpiffeID: domains[0]}}); lerr != nil {
			return lerr
		}
		return authz.New(tx).GrantOwner(ctx, subj.TenantID, authz.Certificate, certID, subj.UserID)
	})
	if errors.Is(err, store.ErrConflict) {
		return CertificateView{}, invalid("certificate", "this certificate is already in lcm")
	}
	if err != nil {
		return CertificateView{}, err
	}
	s.emit(ctx, audit.Event{TenantID: subj.TenantID, EventType: audit.CertificateImported, ActorKind: subj.ActorKind(), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectCertificate, SubjectID: certID, SubjectName: domains[0], Outcome: audit.OutcomeOK,
		Details: map[string]any{"domains": strings.Join(domains, ","), "issuer_id": in.IssuerID, "serial": row.Serial,
			"issuer_dn": leaf.Issuer.String(), "auto_renew": in.AutoRenew}})

	stored, err := s.st.GetCertificate(ctx, subj.TenantID, certID)
	if err != nil {
		return CertificateView{}, err
	}
	perms, _, _, _ := s.az.Effective(ctx, subj, authz.Certificate, certID)
	return s.certView(stored, perms), nil
}

// parseImportCerts returns the leaf (the first certificate of certPEM) and the
// canonical PEM of the chain (the rest of certPEM, then chainPEM; duplicates
// of the leaf or of each other dropped). Only CERTIFICATE blocks are accepted.
func parseImportCerts(certPEM, chainPEM string) (*x509.Certificate, string, error) {
	if len(certPEM) > MaxImportPEMBytes || len(chainPEM) > MaxImportPEMBytes {
		return nil, "", invalid("certificate", "certificate input is too large")
	}
	var certs []*x509.Certificate
	for _, src := range []string{certPEM, chainPEM} {
		rest := []byte(src)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				return nil, "", invalid("certificate", "only CERTIFICATE blocks are accepted (the private key goes in its own field)")
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, "", invalid("certificate", "a certificate could not be parsed")
			}
			certs = append(certs, c)
		}
		if strings.TrimSpace(string(rest)) != "" {
			return nil, "", invalid("certificate", "the input contains text that is not PEM")
		}
	}
	if len(certs) == 0 {
		return nil, "", invalid("certificate", "no certificate found")
	}
	leaf := certs[0]
	if leaf.IsCA {
		return nil, "", invalid("certificate", "the first certificate must be the server certificate, not a CA")
	}
	var chain []string
	seen := map[string]bool{string(leaf.Raw): true}
	for _, c := range certs[1:] {
		if seen[string(c.Raw)] {
			continue
		}
		seen[string(c.Raw)] = true
		chain = append(chain, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))))
	}
	if len(chain) > maxImportChain {
		return nil, "", invalid("chain", "the chain has too many certificates")
	}
	return leaf, strings.Join(chain, "\n"), nil
}

// importDomains returns the DNS names lcm renews the certificate for: the
// leaf's DNS SANs (its CN when it has none), validated like an ACME order.
func importDomains(leaf *x509.Certificate) ([]string, error) {
	if len(leaf.IPAddresses) > 0 || len(leaf.URIs) > 0 || len(leaf.EmailAddresses) > 0 {
		return nil, invalid("certificate", "only certificates for DNS names can be renewed through ACME")
	}
	names := leaf.DNSNames
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	if len(names) == 0 {
		return nil, invalid("certificate", "the certificate names no DNS domain")
	}
	domains, err := validateACMEDomains(names)
	if err != nil {
		var ve *ValidationError
		if errors.As(err, &ve) {
			return nil, invalid("certificate", "certificate domains: "+ve.Message)
		}
		return nil, err
	}
	return domains, nil
}

// parseImportKey parses an unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC private
// key, requires a key an ACME CA accepts (RSA >= 2048 bits, ECDSA P-256 or
// P-384) that matches the leaf, and returns it as PKCS#8 PEM.
func parseImportKey(keyPEM string, leaf *x509.Certificate) ([]byte, error) {
	if len(keyPEM) > MaxImportPEMBytes {
		return nil, invalid("key", "private key input is too large")
	}
	var blk *pem.Block
	rest := []byte(keyPEM)
	for {
		blk, rest = pem.Decode(rest)
		if blk == nil || strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			break
		}
	}
	if blk == nil {
		return nil, invalid("key", "no private key found")
	}
	if blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["Proc-Type"] != "" {
		return nil, invalid("key", "encrypted private keys are not supported; export it without a passphrase")
	}
	var key crypto.Signer
	switch blk.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, invalid("key", "the private key could not be parsed")
		}
		sg, ok := k.(crypto.Signer)
		if !ok {
			return nil, invalid("key", "unsupported private key type")
		}
		key = sg
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, invalid("key", "the private key could not be parsed")
		}
		key = k
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, invalid("key", "the private key could not be parsed")
		}
		key = k
	default:
		return nil, invalid("key", "unsupported private key type")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, invalid("key", "RSA keys must have at least 2048 bits")
		}
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, invalid("key", "ECDSA keys must use P-256 or P-384")
		}
	default:
		return nil, invalid("key", "only RSA and ECDSA keys can be renewed through ACME")
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) {
		return nil, invalid("key", "the private key does not match the certificate")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
