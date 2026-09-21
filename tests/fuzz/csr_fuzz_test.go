package fuzz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/lcm/internal/csr"
)

func sampleCSR(t testing.TB) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc"}, DNSNames: []string{"a.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// FuzzCSR: the CSR parser never panics and only returns (nil,err) or (cert,nil).
func FuzzCSR(f *testing.F) {
	f.Add(sampleCSR(f))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----"))
	f.Add([]byte(""))
	f.Add([]byte(strings.Repeat("A", 1<<15)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := csr.ParseCSR(raw)
		if (got == nil) == (err == nil) {
			t.Fatalf("ParseCSR must return exactly one of value/err: got=%v err=%v", got, err)
		}
	})
}

// FuzzSPIFFEID: the SPIFFE-id validator never panics.
func FuzzSPIFFEID(f *testing.F) {
	f.Add("spiffe://example.org/svc/api")
	f.Add("spiffe://EXAMPLE.org/x")
	f.Add("https://example.org/x")
	f.Add("spiffe://example.org")
	f.Add("spiffe://example.org/%00")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := csr.ParseSPIFFEID(s)
		if err == nil && id.String() == "" {
			t.Fatalf("accepted id renders empty: %q", s)
		}
	})
}

// FuzzBundle: the PEM/bundle encoders never panic on arbitrary DER and the
// SAN validator never panics.
func FuzzBundle(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, "a.example")
	f.Add([]byte(""), "")
	f.Add([]byte(strings.Repeat("\xff", 500)), "x,y,z")
	f.Fuzz(func(t *testing.T, der []byte, sans string) {
		_ = csr.EncodeCertPEM(der)
		_ = csr.EncodeChainPEM([][]byte{der, der})
		_ = csr.Fingerprint(der)
		req := strings.Split(sans, ",")
		_ = csr.ValidateSANs(req, req)
	})
}
