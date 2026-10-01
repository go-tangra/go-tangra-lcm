package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // test mirrors the display fingerprint.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type issued struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func (i issued) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.der}))
}

func mint(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, parent *issued) issued {
	t.Helper()
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issued{cert: c, der: der, key: key}
}

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t *testing.T) issued {
	t.Helper()
	return mint(t, &x509.Certificate{
		SerialNumber:          big.NewInt(0x0102),
		Subject:               pkix.Name{CommonName: "Test Root CA", Organization: []string{"Tangra"}},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}, ecKey(t, elliptic.P384()), nil)
}

func decodeOK(t *testing.T, certPEM, chainPEM string) Details {
	t.Helper()
	r := Decode(certPEM, chainPEM, now)
	if !r.Available || r.Details == nil || r.Error != "" || r.Source != "certificate" {
		t.Fatalf("decode: %+v", r)
	}
	return *r.Details
}

func TestRSALeafAllFields(t *testing.T) {
	ca := newCA(t)
	spiffe, _ := url.Parse("spiffe://example.org/ns/prod/sa/api")
	web, _ := url.Parse("https://api.example.org/id")
	leaf := mint(t, &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes([]byte{0x0a, 0xbc, 0xde, 0xf0}),
		Subject:               pkix.Name{CommonName: "api.example.org", Organization: []string{"Example"}, Country: []string{"BG"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10*24*time.Hour + time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}},
		BasicConstraintsValid: true,
		DNSNames:              []string{"api.example.org", "www.example.org"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.7"), net.ParseIP("2001:db8::1")},
		URIs:                  []*url.URL{spiffe, web},
		EmailAddresses:        []string{"ops@example.org"},
		CRLDistributionPoints: []string{"http://crl.example.org/root.crl"},
		OCSPServer:            []string{"http://ocsp.example.org"},
		IssuingCertificateURL: []string{"http://ca.example.org/root.crt"},
		SubjectKeyId:          []byte{0xde, 0xad, 0xbe, 0xef},
	}, rsaKey(t), &ca)

	d := decodeOK(t, leaf.pem(), ca.pem())

	if d.Subject.CN != "api.example.org" || !strings.Contains(d.Subject.DN, "CN=api.example.org") || !strings.Contains(d.Subject.DN, "O=Example") || !strings.Contains(d.Subject.DN, "C=BG") {
		t.Errorf("subject %+v", d.Subject)
	}
	if d.Issuer.CN != "Test Root CA" || !strings.Contains(d.Issuer.DN, "O=Tangra") {
		t.Errorf("issuer %+v", d.Issuer)
	}
	if d.SelfSigned {
		t.Error("leaf reported self-signed")
	}
	if d.Serial != "0A:BC:DE:F0" {
		t.Errorf("serial %q", d.Serial)
	}
	if d.Version != 3 {
		t.Errorf("version %d", d.Version)
	}
	if !d.Validity.NotBefore.Equal(leaf.cert.NotBefore) || !d.Validity.NotAfter.Equal(leaf.cert.NotAfter) || d.Validity.NotAfter.Location() != time.UTC {
		t.Errorf("validity %+v", d.Validity)
	}
	if d.Validity.Status != StatusValid || d.Validity.DaysRemaining != 10 {
		t.Errorf("status %+v", d.Validity)
	}
	if !reflect.DeepEqual(d.SANs.DNS, []string{"api.example.org", "www.example.org"}) {
		t.Errorf("dns %v", d.SANs.DNS)
	}
	if !reflect.DeepEqual(d.SANs.IP, []string{"10.0.0.7", "2001:db8::1"}) {
		t.Errorf("ip %v", d.SANs.IP)
	}
	if !reflect.DeepEqual(d.SANs.URI, []string{"spiffe://example.org/ns/prod/sa/api", "https://api.example.org/id"}) {
		t.Errorf("uri %v", d.SANs.URI)
	}
	if !reflect.DeepEqual(d.SANs.SPIFFE, []string{"spiffe://example.org/ns/prod/sa/api"}) {
		t.Errorf("spiffe %v", d.SANs.SPIFFE)
	}
	if !reflect.DeepEqual(d.SANs.Email, []string{"ops@example.org"}) {
		t.Errorf("email %v", d.SANs.Email)
	}
	if d.PublicKey != (PublicKey{Algorithm: "RSA", Size: 2048}) {
		t.Errorf("public key %+v", d.PublicKey)
	}
	if d.SignatureAlgorithm != "ECDSA-SHA384" {
		t.Errorf("signature algorithm %q", d.SignatureAlgorithm)
	}
	if !reflect.DeepEqual(d.KeyUsage, []string{"Digital Signature", "Key Encipherment"}) {
		t.Errorf("key usage %v", d.KeyUsage)
	}
	if !reflect.DeepEqual(d.ExtKeyUsage, []string{"Server Authentication", "Client Authentication", "1.3.6.1.4.1.99999.1"}) {
		t.Errorf("eku %v", d.ExtKeyUsage)
	}
	if d.BasicConstraints.CA || !d.BasicConstraints.Present || d.BasicConstraints.PathLen != nil {
		t.Errorf("basic constraints %+v", d.BasicConstraints)
	}
	if d.SubjectKeyID != "DE:AD:BE:EF" {
		t.Errorf("ski %q", d.SubjectKeyID)
	}
	if d.AuthorityKeyID == "" || d.AuthorityKeyID != colonHex(ca.cert.SubjectKeyId) {
		t.Errorf("aki %q want %q", d.AuthorityKeyID, colonHex(ca.cert.SubjectKeyId))
	}
	if !reflect.DeepEqual(d.CRLDistributionPoints, []string{"http://crl.example.org/root.crl"}) ||
		!reflect.DeepEqual(d.OCSPServers, []string{"http://ocsp.example.org"}) ||
		!reflect.DeepEqual(d.IssuingCertificateURLs, []string{"http://ca.example.org/root.crt"}) {
		t.Errorf("urls %v %v %v", d.CRLDistributionPoints, d.OCSPServers, d.IssuingCertificateURLs)
	}
	s256 := sha256.Sum256(leaf.der)
	s1 := sha1.Sum(leaf.der) //nolint:gosec // test.
	if d.Fingerprints.SHA256 != colonHex(s256[:]) || d.Fingerprints.SHA1 != colonHex(s1[:]) || len(d.Fingerprints.SHA256) != 32*3-1 {
		t.Errorf("fingerprints %+v", d.Fingerprints)
	}
	// The chain: the CA certificate.
	if len(d.Chain) != 1 || d.ChainError != "" {
		t.Fatalf("chain %+v %q", d.Chain, d.ChainError)
	}
	caSum := sha256.Sum256(ca.der)
	c := d.Chain[0]
	if c.Subject.CN != "Test Root CA" || c.Issuer.CN != "Test Root CA" || !c.NotAfter.Equal(ca.cert.NotAfter) || c.FingerprintSHA256 != colonHex(caSum[:]) {
		t.Errorf("chain entry %+v", c)
	}
}

func TestECDSALeaf(t *testing.T) {
	ca := newCA(t)
	leaf := mint(t, &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "svc"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, ecKey(t, elliptic.P256()), &ca)
	d := decodeOK(t, leaf.pem(), "")
	if d.PublicKey != (PublicKey{Algorithm: "ECDSA", Size: 256, Curve: "P-256"}) {
		t.Errorf("public key %+v", d.PublicKey)
	}
	if d.Serial != "07" {
		t.Errorf("serial %q", d.Serial)
	}
	if d.BasicConstraints.Present || d.BasicConstraints.CA {
		t.Errorf("basic constraints %+v", d.BasicConstraints)
	}
	if d.Validity.Status != StatusValid || d.Validity.DaysRemaining != 0 {
		t.Errorf("validity %+v", d.Validity)
	}
	// Empty collections are [] in JSON, never null.
	if len(d.Chain) != 0 || d.Chain == nil || d.SANs.DNS == nil || d.ExtKeyUsage == nil || d.CRLDistributionPoints == nil {
		t.Errorf("nil slices %+v", d)
	}
}

func TestCAWithPathLen(t *testing.T) {
	ca := newCA(t)
	d := decodeOK(t, ca.pem(), "")
	if !d.BasicConstraints.CA || d.BasicConstraints.PathLen == nil || *d.BasicConstraints.PathLen != 1 {
		t.Errorf("basic constraints %+v", d.BasicConstraints)
	}
	if !d.SelfSigned || d.Subject != d.Issuer {
		t.Errorf("self-signed %v %+v %+v", d.SelfSigned, d.Subject, d.Issuer)
	}
	if !reflect.DeepEqual(d.KeyUsage, []string{"Certificate Sign", "CRL Sign"}) {
		t.Errorf("key usage %v", d.KeyUsage)
	}
	if d.PublicKey.Curve != "P-384" || d.Serial != "01:02" {
		t.Errorf("pk %+v serial %q", d.PublicKey, d.Serial)
	}

	// Path length zero is reported as 0; an unconstrained CA has none.
	zero := mint(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "z"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, ecKey(t, elliptic.P256()), nil)
	if z := decodeOK(t, zero.pem(), ""); z.BasicConstraints.PathLen == nil || *z.BasicConstraints.PathLen != 0 {
		t.Errorf("path len zero %+v", z.BasicConstraints)
	}
	unl := mint(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "u"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign}, ecKey(t, elliptic.P256()), nil)
	if u := decodeOK(t, unl.pem(), ""); !u.BasicConstraints.CA || u.BasicConstraints.PathLen != nil {
		t.Errorf("unconstrained %+v", u.BasicConstraints)
	}
}

func TestExpiredAndNotYetValid(t *testing.T) {
	ca := newCA(t)
	expired := mint(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "old"},
		NotBefore: now.Add(-40 * 24 * time.Hour), NotAfter: now.Add(-3*24*time.Hour - time.Hour)}, ecKey(t, elliptic.P256()), &ca)
	d := decodeOK(t, expired.pem(), "")
	if d.Validity.Status != StatusExpired || d.Validity.DaysRemaining != -4 {
		t.Errorf("expired %+v", d.Validity)
	}
	future := mint(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "new"},
		NotBefore: now.Add(24 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, ecKey(t, elliptic.P256()), &ca)
	if d := decodeOK(t, future.pem(), ""); d.Validity.Status != StatusNotYetValid {
		t.Errorf("not yet valid %+v", d.Validity)
	}
}

func TestEd25519AndLongChain(t *testing.T) {
	root := newCA(t)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inter := mint(t, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(1000 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, ecKey(t, elliptic.P256()), &root)
	leaf := mint(t, &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "edge"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, edPriv, &inter)

	// The chain is the intermediate then the root; a non-certificate block
	// between them is ignored.
	chain := inter.pem() + "-----BEGIN NOTE-----\nAAAA\n-----END NOTE-----\n" + root.pem()
	d := decodeOK(t, leaf.pem(), chain)
	if d.PublicKey != (PublicKey{Algorithm: "Ed25519", Size: 256}) {
		t.Errorf("public key %+v", d.PublicKey)
	}
	if d.Issuer.CN != "Intermediate" || len(d.Chain) != 2 || d.Chain[0].Subject.CN != "Intermediate" || d.Chain[0].Issuer.CN != "Test Root CA" || d.Chain[1].Subject.CN != "Test Root CA" {
		t.Errorf("chain %+v", d.Chain)
	}
}

func TestUnavailable(t *testing.T) {
	ca := newCA(t)
	keyDER, _ := x509.MarshalECPrivateKey(ecKey(t, elliptic.P256()))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))
	for name, in := range map[string]string{
		"empty":     "  \n",
		"not pem":   "hello world",
		"key only":  keyPEM,
		"bad der":   garbage,
		"truncated": ca.pem()[:120],
	} {
		t.Run(name, func(t *testing.T) {
			r := Decode(in, ca.pem(), now)
			if r.Available || r.Details != nil || r.Error != ErrUnavailable || r.Reason == "" || r.Source != "certificate" {
				t.Fatalf("result %+v", r)
			}
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), "details\"") {
				t.Fatalf("leaks or carries details: %s", b)
			}
		})
	}

	// A private key stored before the certificate is skipped, never echoed.
	d := decodeOK(t, keyPEM+ca.pem(), "")
	if d.Subject.CN != "Test Root CA" {
		t.Fatalf("subject %+v", d.Subject)
	}
}

func TestChainErrorKeepsLeaf(t *testing.T) {
	ca := newCA(t)
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x01}}))
	d := decodeOK(t, ca.pem(), bad+ca.pem())
	if d.ChainError == "" || len(d.Chain) != 1 {
		t.Fatalf("chain %+v %q", d.Chain, d.ChainError)
	}
}

func TestHelpers(t *testing.T) {
	if colonHex(nil) != "" || colonHex([]byte{0, 0xff}) != "00:FF" {
		t.Fatal("colonHex")
	}
	long := strings.Repeat("x ", 300)
	if b := bounded(long); len(b) > maxReason+len("…") {
		t.Fatalf("bounded len %d", len(b))
	}
	if serial(&x509.Certificate{}) != "" || serial(&x509.Certificate{SerialNumber: big.NewInt(0)}) != "00" || serial(&x509.Certificate{SerialNumber: big.NewInt(-5)}) != "-05" {
		t.Fatal("serial")
	}
	if got := extKeyUsage(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsage(999)}}); !reflect.DeepEqual(got, []string{"EKU 999"}) {
		t.Fatalf("eku %v", got)
	}
	if pk := publicKey(&x509.Certificate{PublicKeyAlgorithm: x509.DSA}); pk.Algorithm != "DSA" {
		t.Fatalf("pk %+v", pk)
	}
}
