// Package csr validates certificate-signing requests before the CA ever signs
// them: every input is size-bounded, PEM and ASN.1 are parsed defensively, the
// request's own signature is checked, weak keys are refused (ECDSA below P-256,
// RSA below 2048 bits), the requested SPIFFE identity is parsed against a strict
// grammar, and the DNS SANs the CSR carries must be a subset of what policy
// authorised — so a malformed or over-reaching request is rejected as data, not
// trusted as a certificate (SR-CSR).
package csr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
)

// MaxCSRBytes bounds the PEM input handed to ParseCSR.
const MaxCSRBytes = 16 << 10

// MaxSPIFFEIDBytes bounds a SPIFFE ID string.
const MaxSPIFFEIDBytes = 2048

// Errors.
var (
	ErrTooLarge = errors.New("csr: input exceeds size bound")
	ErrParse    = errors.New("csr: request could not be parsed")
	ErrSPIFFEID = errors.New("csr: invalid SPIFFE ID")
	ErrWeakKey  = errors.New("csr: public key is too weak")
	ErrSANs     = errors.New("csr: requested SANs are not authorised")
)

// SPIFFEID is a parsed spiffe://<trust-domain>/<path> identity.
type SPIFFEID struct {
	TrustDomain string
	Path        string
	Raw         string
}

// String renders the canonical spiffe:// form.
func (id SPIFFEID) String() string {
	return "spiffe://" + id.TrustDomain + "/" + id.Path
}

// ParseSPIFFEID parses and validates a SPIFFE ID: scheme spiffe, a non-empty
// lowercase trust domain (letters, digits, dots, hyphens, at most 253 bytes), a
// non-empty path, no userinfo, query, fragment or port, no control characters,
// and at most MaxSPIFFEIDBytes overall.
func ParseSPIFFEID(s string) (SPIFFEID, error) {
	if len(s) == 0 || len(s) > MaxSPIFFEIDBytes || hasControl(s) {
		return SPIFFEID{}, ErrSPIFFEID
	}
	u, err := url.Parse(s)
	if err != nil {
		return SPIFFEID{}, ErrSPIFFEID
	}
	if u.Scheme != "spiffe" || u.Opaque != "" {
		return SPIFFEID{}, ErrSPIFFEID
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return SPIFFEID{}, ErrSPIFFEID
	}
	if u.Port() != "" {
		return SPIFFEID{}, ErrSPIFFEID
	}
	host := u.Hostname()
	if host == "" || len(host) > 253 || !validTrustDomain(host) {
		return SPIFFEID{}, ErrSPIFFEID
	}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" || hasControl(path) {
		return SPIFFEID{}, ErrSPIFFEID
	}
	return SPIFFEID{TrustDomain: host, Path: path, Raw: s}, nil
}

// hasControl reports whether s contains an ASCII control character (including
// DEL), which a SPIFFE ID must never carry.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// validTrustDomain reports whether host is a non-empty run of lowercase
// letters, digits, dots and hyphens.
func validTrustDomain(host string) bool {
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// ParsedCSR is the validated view of a certificate-signing request.
type ParsedCSR struct {
	CSR           *x509.CertificateRequest
	DNSNames      []string
	URIs          []string
	PublicKeyBits int
}

// ParseCSR decodes a PEM "CERTIFICATE REQUEST", parses it, verifies its
// self-signature and rejects weak keys. It never panics on bad input: it
// returns either (nil, error) or (non-nil, nil).
func ParseCSR(pemBytes []byte) (*ParsedCSR, error) {
	if len(pemBytes) > MaxCSRBytes {
		return nil, ErrTooLarge
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, ErrParse
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, ErrParse
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrParse
	}
	bits, err := keyStrength(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	uris := make([]string, 0, len(csr.URIs))
	for _, u := range csr.URIs {
		uris = append(uris, u.String())
	}
	return &ParsedCSR{
		CSR:           csr,
		DNSNames:      csr.DNSNames,
		URIs:          uris,
		PublicKeyBits: bits,
	}, nil
}

// keyStrength returns the key size in bits and rejects weak keys: ECDSA below
// P-256, RSA below 2048 bits. Ed25519 is always accepted (256 bits).
func keyStrength(pub any) (int, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < 2048 {
			return 0, ErrWeakKey
		}
		return bits, nil
	case *ecdsa.PublicKey:
		bits := k.Curve.Params().BitSize
		if bits < 256 {
			return 0, ErrWeakKey
		}
		return bits, nil
	case ed25519.PublicKey:
		return 256, nil
	default:
		return 0, ErrWeakKey
	}
}

// ValidateSANs requires every DNS SAN the CSR provided to appear (case
// insensitively) in the requested/authorised set. An empty csrProvided is
// always allowed.
func ValidateSANs(requested, csrProvided []string) error {
	allowed := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		allowed[strings.ToLower(name)] = struct{}{}
	}
	for _, name := range csrProvided {
		if _, ok := allowed[strings.ToLower(name)]; !ok {
			return ErrSANs
		}
	}
	return nil
}

// EncodeCertPEM wraps a single DER certificate in a PEM CERTIFICATE block.
func EncodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// EncodeChainPEM concatenates DER certificates as PEM CERTIFICATE blocks, in
// the order given.
func EncodeChainPEM(ders [][]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, EncodeCertPEM(der)...)
	}
	return out
}

// Fingerprint is the lowercase hex SHA-256 of a DER certificate, without
// separators.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
