// Package certinfo decodes an X.509 certificate into the read-only details the
// certificate drawer shows. Every value is read from the certificate bytes
// themselves (crypto/x509), never from database columns or the original
// request, so what an operator sees is what a relying party would see.
//
// Only certificates are decoded: any other PEM block (a private key that was
// stored alongside by mistake, for instance) is skipped and never echoed.
package certinfo

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are a display convention, not a security decision.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// ErrUnavailable is the error code reported when the stored certificate cannot
// be decoded (no PEM, no CERTIFICATE block, or unparseable DER).
const ErrUnavailable = "details_unavailable"

// Validity statuses, computed from the certificate's own dates.
const (
	StatusNotYetValid = "not_yet_valid"
	StatusValid       = "valid"
	StatusExpired     = "expired"
)

// maxReason bounds a parse-failure reason so a hostile blob cannot inflate it.
const maxReason = 200

// Result is the response for one stored certificate: either decoded details,
// or Available=false with a machine code (Error) and a human Reason.
type Result struct {
	Available bool     `json:"available"`
	Source    string   `json:"source"`
	Error     string   `json:"error,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Details   *Details `json:"details,omitempty"`
}

// Name is a distinguished name: the full RFC 2253 string and its common name.
type Name struct {
	DN string `json:"dn"`
	CN string `json:"cn"`
}

// Validity is the certificate's validity window and its status at decode time.
type Validity struct {
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Status        string    `json:"status"`
	DaysRemaining int       `json:"days_remaining"`
}

// SANs are the subject alternative names grouped by type. URIs include SPIFFE
// IDs, which are also listed on their own.
type SANs struct {
	DNS    []string `json:"dns"`
	IP     []string `json:"ip"`
	URI    []string `json:"uri"`
	SPIFFE []string `json:"spiffe"`
	Email  []string `json:"email"`
}

// PublicKey describes the subject public key (never the private key).
type PublicKey struct {
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

// BasicConstraints is the basicConstraints extension. PathLen is nil when the
// path length is unconstrained or the extension is absent.
type BasicConstraints struct {
	Present bool `json:"present"`
	CA      bool `json:"ca"`
	PathLen *int `json:"path_len,omitempty"`
}

// Fingerprints are digests of the DER encoding, colon-separated upper hex.
type Fingerprints struct {
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
}

// ChainEntry is one certificate of the stored chain.
type ChainEntry struct {
	Subject           Name      `json:"subject"`
	Issuer            Name      `json:"issuer"`
	NotAfter          time.Time `json:"not_after"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

// Details are the decoded fields of the leaf certificate.
type Details struct {
	Subject                Name             `json:"subject"`
	Issuer                 Name             `json:"issuer"`
	SelfSigned             bool             `json:"self_signed"`
	Serial                 string           `json:"serial"`
	Version                int              `json:"version"`
	Validity               Validity         `json:"validity"`
	SANs                   SANs             `json:"sans"`
	PublicKey              PublicKey        `json:"public_key"`
	SignatureAlgorithm     string           `json:"signature_algorithm"`
	KeyUsage               []string         `json:"key_usage"`
	ExtKeyUsage            []string         `json:"ext_key_usage"`
	BasicConstraints       BasicConstraints `json:"basic_constraints"`
	SubjectKeyID           string           `json:"subject_key_id,omitempty"`
	AuthorityKeyID         string           `json:"authority_key_id,omitempty"`
	CRLDistributionPoints  []string         `json:"crl_distribution_points"`
	OCSPServers            []string         `json:"ocsp_servers"`
	IssuingCertificateURLs []string         `json:"issuing_certificate_urls"`
	Fingerprints           Fingerprints     `json:"fingerprints"`
	Chain                  []ChainEntry     `json:"chain"`
	ChainError             string           `json:"chain_error,omitempty"`
}

// Decode parses the leaf certificate in certPEM (and the optional chain in
// chainPEM) and computes the validity status at now. A leaf that cannot be
// decoded yields Available=false with a reason instead of an error: the
// caller still answers 200 so the drawer can show a clear state.
func Decode(certPEM, chainPEM string, now time.Time) Result {
	leaf, err := firstCertificate([]byte(certPEM))
	if err != nil {
		return Result{Available: false, Source: "certificate", Error: ErrUnavailable, Reason: bounded(err.Error())}
	}
	d := describe(leaf, now)
	chain, cerr := parseChain([]byte(chainPEM))
	d.Chain = chain
	if cerr != nil {
		d.ChainError = bounded(cerr.Error())
	}
	return Result{Available: true, Source: "certificate", Details: &d}
}

var (
	errNoPEM  = errors.New("no certificate is stored")
	errNoCert = errors.New("the stored data contains no PEM CERTIFICATE block")
)

// firstCertificate returns the first CERTIFICATE block of data, parsed. Other
// block types are skipped without being inspected further.
func firstCertificate(data []byte) (*x509.Certificate, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errNoPEM
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, errNoCert
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the certificate could not be parsed: %w", err)
		}
		return c, nil
	}
}

// parseChain decodes every CERTIFICATE block of the chain. Entries that parse
// are kept even when a later one fails; the failure is reported separately.
func parseChain(data []byte) ([]ChainEntry, error) {
	out := []ChainEntry{}
	var firstErr error
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out, firstErr
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("a chain certificate could not be parsed: %w", err)
			}
			continue
		}
		sum := sha256.Sum256(c.Raw)
		out = append(out, ChainEntry{Subject: name(c.Subject), Issuer: name(c.Issuer), NotAfter: c.NotAfter.UTC(), FingerprintSHA256: colonHex(sum[:])})
	}
}

func describe(c *x509.Certificate, now time.Time) Details {
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw) //nolint:gosec // display fingerprint only.
	d := Details{
		Subject:                name(c.Subject),
		Issuer:                 name(c.Issuer),
		SelfSigned:             string(c.RawSubject) == string(c.RawIssuer) && c.CheckSignatureFrom(c) == nil,
		Serial:                 serial(c),
		Version:                c.Version,
		Validity:               validity(c, now),
		SANs:                   sans(c),
		PublicKey:              publicKey(c),
		SignatureAlgorithm:     c.SignatureAlgorithm.String(),
		KeyUsage:               keyUsage(c.KeyUsage),
		ExtKeyUsage:            extKeyUsage(c),
		BasicConstraints:       basicConstraints(c),
		SubjectKeyID:           colonHex(c.SubjectKeyId),
		AuthorityKeyID:         colonHex(c.AuthorityKeyId),
		CRLDistributionPoints:  nonNil(c.CRLDistributionPoints),
		OCSPServers:            nonNil(c.OCSPServer),
		IssuingCertificateURLs: nonNil(c.IssuingCertificateURL),
		Fingerprints:           Fingerprints{SHA256: colonHex(s256[:]), SHA1: colonHex(s1[:])},
	}
	return d
}

func name(n pkix.Name) Name { return Name{DN: n.String(), CN: n.CommonName} }

func serial(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	b := c.SerialNumber.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	s := colonHex(b)
	if c.SerialNumber.Sign() < 0 {
		s = "-" + s
	}
	return s
}

// validity computes the status from the certificate's own NotBefore/NotAfter.
// DaysRemaining counts whole days to NotAfter (negative once expired).
func validity(c *x509.Certificate, now time.Time) Validity {
	v := Validity{NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()}
	switch {
	case now.Before(c.NotBefore):
		v.Status = StatusNotYetValid
	case now.After(c.NotAfter):
		v.Status = StatusExpired
	default:
		v.Status = StatusValid
	}
	v.DaysRemaining = int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
	return v
}

func sans(c *x509.Certificate) SANs {
	s := SANs{DNS: nonNil(c.DNSNames), IP: []string{}, URI: []string{}, SPIFFE: []string{}, Email: nonNil(c.EmailAddresses)}
	for _, ip := range c.IPAddresses {
		s.IP = append(s.IP, ip.String())
	}
	for _, u := range c.URIs {
		s.URI = append(s.URI, u.String())
		if strings.EqualFold(u.Scheme, "spiffe") {
			s.SPIFFE = append(s.SPIFFE, u.String())
		}
	}
	return s
}

func publicKey(c *x509.Certificate) PublicKey {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return PublicKey{Algorithm: "RSA", Size: k.N.BitLen()}
	case *ecdsa.PublicKey:
		p := k.Curve.Params()
		return PublicKey{Algorithm: "ECDSA", Size: p.BitSize, Curve: p.Name}
	case ed25519.PublicKey:
		return PublicKey{Algorithm: "Ed25519", Size: 256}
	}
	return PublicKey{Algorithm: c.PublicKeyAlgorithm.String()}
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

func keyUsage(ku x509.KeyUsage) []string {
	out := []string{}
	for _, k := range keyUsageNames {
		if ku&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return out
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "Server Authentication",
	x509.ExtKeyUsageClientAuth:                     "Client Authentication",
	x509.ExtKeyUsageCodeSigning:                    "Code Signing",
	x509.ExtKeyUsageEmailProtection:                "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPsec End System",
	x509.ExtKeyUsageIPSECTunnel:                    "IPsec Tunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPsec User",
	x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
}

func extKeyUsage(c *x509.Certificate) []string {
	out := []string{}
	for _, u := range c.ExtKeyUsage {
		if n, ok := extKeyUsageNames[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("EKU %d", int(u)))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, asn1.ObjectIdentifier(oid).String())
	}
	return out
}

func basicConstraints(c *x509.Certificate) BasicConstraints {
	bc := BasicConstraints{Present: c.BasicConstraintsValid, CA: c.BasicConstraintsValid && c.IsCA}
	if bc.CA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		n := c.MaxPathLen
		bc.PathLen = &n
	}
	return bc
}

// colonHex renders bytes as colon-separated upper-case hex ("" for none).
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const digits = "0123456789ABCDEF"
	var sb strings.Builder
	sb.Grow(len(b) * 3)
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(digits[v>>4])
		sb.WriteByte(digits[v&0x0f])
	}
	return sb.String()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string(nil), s...)
}

func bounded(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxReason {
		s = s[:maxReason] + "…"
	}
	return s
}
