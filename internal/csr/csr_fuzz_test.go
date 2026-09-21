package csr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// ecdsaCSRPEM builds a self-signed CSR PEM over the given curve.
func ecdsaCSRPEM(tb testing.TB, curve elliptic.Curve, cn string, dns ...string) []byte {
	tb.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa key: %v", err)
	}
	return csrPEM(tb, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
}

// rsaCSRPEM builds a self-signed CSR PEM with an RSA key of the given size.
func rsaCSRPEM(tb testing.TB, bits int, cn string) []byte {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		tb.Fatalf("rsa key: %v", err)
	}
	return csrPEM(tb, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
}

// ed25519CSRPEM builds a self-signed Ed25519 CSR PEM.
func ed25519CSRPEM(tb testing.TB, cn string) []byte {
	tb.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519 key: %v", err)
	}
	return csrPEM(tb, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
}

func csrPEM(tb testing.TB, tmpl *x509.CertificateRequest, key any) []byte {
	tb.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		tb.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func FuzzCSR(f *testing.F) {
	f.Add(ecdsaCSRPEM(f, elliptic.P256(), "fuzz.example"))
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\nbm90IGRlcg==\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte("not pem at all"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte("A"), MaxCSRBytes+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseCSR(data)
		// The contract: exactly one of (got, err) is set.
		if (got == nil) == (err == nil) {
			t.Fatalf("ParseCSR invariant violated: got=%v err=%v", got, err)
		}
		if got != nil && got.CSR == nil {
			t.Fatalf("ParseCSR returned parsed result with nil CSR")
		}
	})
}

func FuzzSPIFFEID(f *testing.F) {
	seeds := []string{
		"spiffe://example.org/workload/foo",
		"spiffe://a-b.example/svc",
		"",
		"spiffe:///path",
		"spiffe://example.org/",
		"spiffe://example.org",
		"http://example.org/foo",
		"spiffe://EXAMPLE.org/foo",
		"spiffe://user@example.org/foo",
		"spiffe://example.org:8443/foo",
		"spiffe://example.org/foo?q=1",
		"spiffe://example.org/foo#frag",
		"spiffe:opaque",
		"spiffe://example.org/%00",
		"spiffe://example.org/%zz",
		"spiffe://exa\x00mple/foo",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseSPIFFEID(s)
		if err != nil {
			if id != (SPIFFEID{}) {
				t.Fatalf("error result carried a non-zero id: %+v", id)
			}
			return
		}
		if id.TrustDomain == "" || id.Path == "" {
			t.Fatalf("accepted id missing fields: %+v", id)
		}
		// A parsed id must round-trip through its canonical string form.
		again, err := ParseSPIFFEID(id.String())
		if err != nil {
			t.Fatalf("canonical form %q failed to re-parse: %v", id.String(), err)
		}
		if again.TrustDomain != id.TrustDomain || again.Path != id.Path {
			t.Fatalf("round-trip mismatch: %+v vs %+v", id, again)
		}
	})
}

func TestCSR(t *testing.T) {
	t.Run("parse", func(t *testing.T) {
		cases := []struct {
			name    string
			pem     []byte
			wantErr error
			bits    int
		}{
			{"p256 ok", ecdsaCSRPEM(t, elliptic.P256(), "p256.example", "a.example.com"), nil, 256},
			{"p384 ok", ecdsaCSRPEM(t, elliptic.P384(), "p384.example"), nil, 384},
			{"p224 weak", ecdsaCSRPEM(t, elliptic.P224(), "p224.example"), ErrWeakKey, 0},
			{"rsa1024 weak", rsaCSRPEM(t, 1024, "rsa1024.example"), ErrWeakKey, 0},
			{"rsa2048 ok", rsaCSRPEM(t, 2048, "rsa2048.example"), nil, 2048},
			{"ed25519 ok", ed25519CSRPEM(t, "ed.example"), nil, 256},
			{"malformed pem", []byte("not a pem block"), ErrParse, 0},
			{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), ErrParse, 0},
			{"bad der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("not der")}), ErrParse, 0},
			{"oversize", bytes.Repeat([]byte("A"), MaxCSRBytes+1), ErrTooLarge, 0},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := ParseCSR(tc.pem)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if tc.wantErr != nil {
					if got != nil {
						t.Fatalf("want nil result on error, got %+v", got)
					}
					return
				}
				if got == nil || got.CSR == nil {
					t.Fatalf("want parsed result, got nil")
				}
				if got.PublicKeyBits != tc.bits {
					t.Fatalf("bits = %d, want %d", got.PublicKeyBits, tc.bits)
				}
			})
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		const cn = "csrtampertoken"
		p := ecdsaCSRPEM(t, elliptic.P256(), cn)
		block, _ := pem.Decode(p)
		if block == nil {
			t.Fatal("decode seed")
		}
		der := append([]byte(nil), block.Bytes...)
		if bytes.Index(der, []byte(cn)) < 0 {
			t.Fatal("CN not found in DER")
		}
		// Corrupt the trailing signature bytes: the ASN.1 structure still
		// parses, but CheckSignature must reject it.
		der[len(der)-1] ^= 0xff
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		if _, err := ParseCSR(bad); !errors.Is(err, ErrParse) {
			t.Fatalf("tampered CSR err = %v, want ErrParse", err)
		}
	})

	t.Run("key strength unsupported", func(t *testing.T) {
		if _, err := keyStrength("not a key"); !errors.Is(err, ErrWeakKey) {
			t.Fatalf("unsupported key err = %v, want ErrWeakKey", err)
		}
	})

	t.Run("uri sans recorded", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := ParseSPIFFEID("spiffe://example.org/svc/uri")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(id.String())
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "uri.example"},
			URIs:     []*url.URL{u},
			DNSNames: []string{"host.example.com"},
		}, key)
		if err != nil {
			t.Fatalf("create csr: %v", err)
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		got, err := ParseCSR(p)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(got.URIs) != 1 || got.URIs[0] != id.String() {
			t.Fatalf("URIs = %v, want [%s]", got.URIs, id.String())
		}
		if len(got.DNSNames) != 1 || got.DNSNames[0] != "host.example.com" {
			t.Fatalf("DNSNames = %v", got.DNSNames)
		}
	})

	t.Run("spiffe happy", func(t *testing.T) {
		id, err := ParseSPIFFEID("spiffe://example.org/workload/db")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if id.TrustDomain != "example.org" || id.Path != "workload/db" {
			t.Fatalf("parsed = %+v", id)
		}
		if id.Raw != "spiffe://example.org/workload/db" {
			t.Fatalf("raw = %q", id.Raw)
		}
		if id.String() != "spiffe://example.org/workload/db" {
			t.Fatalf("String = %q", id.String())
		}
	})

	t.Run("spiffe rejects", func(t *testing.T) {
		bad := []string{
			"",
			strings.Repeat("a", MaxSPIFFEIDBytes+1),
			"spiffe://example.org/foo\x01bar",
			"spiffe://example.org/%zz",
			"http://example.org/foo",
			"spiffe:opaque",
			"spiffe://user@example.org/foo",
			"spiffe://example.org/foo?q=1",
			"spiffe://example.org/foo?",
			"spiffe://example.org/foo#f",
			"spiffe://example.org:8443/foo",
			"spiffe:///foo",
			"spiffe://" + strings.Repeat("a", 254) + "/foo",
			"spiffe://EXAMPLE.org/foo",
			"spiffe://exa_mple/foo",
			"spiffe://example.org/",
			"spiffe://example.org",
			"spiffe://example.org/%00",
		}
		for _, s := range bad {
			if _, err := ParseSPIFFEID(s); !errors.Is(err, ErrSPIFFEID) {
				t.Fatalf("ParseSPIFFEID(%q) err = %v, want ErrSPIFFEID", s, err)
			}
		}
	})

	t.Run("validate sans", func(t *testing.T) {
		if err := ValidateSANs([]string{"A.example.com", "b.example.com"}, []string{"a.EXAMPLE.com"}); err != nil {
			t.Fatalf("subset should pass: %v", err)
		}
		if err := ValidateSANs([]string{"a.example.com"}, nil); err != nil {
			t.Fatalf("empty provided should pass: %v", err)
		}
		if err := ValidateSANs([]string{"a.example.com"}, []string{"a.example.com", "evil.example.com"}); !errors.Is(err, ErrSANs) {
			t.Fatalf("superset should fail: %v", err)
		}
	})

	t.Run("encode chain order", func(t *testing.T) {
		a := []byte{0x30, 0x03, 0x01, 0x01, 0x00}
		b := []byte{0x30, 0x03, 0x01, 0x01, 0x01}
		chain := EncodeChainPEM([][]byte{a, b})
		if !bytes.Equal(EncodeCertPEM(a), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a})) {
			t.Fatal("EncodeCertPEM mismatch")
		}
		var ders [][]byte
		rest := chain
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				t.Fatalf("block type = %q", blk.Type)
			}
			ders = append(ders, blk.Bytes)
		}
		if len(ders) != 2 || !bytes.Equal(ders[0], a) || !bytes.Equal(ders[1], b) {
			t.Fatalf("chain order wrong: %v", ders)
		}
		if EncodeChainPEM(nil) != nil {
			t.Fatal("empty chain should be nil")
		}
	})

	t.Run("fingerprint stable", func(t *testing.T) {
		der := []byte("some certificate der bytes")
		f1 := Fingerprint(der)
		f2 := Fingerprint(der)
		if f1 != f2 {
			t.Fatalf("not stable: %q vs %q", f1, f2)
		}
		if len(f1) != 64 {
			t.Fatalf("len = %d, want 64", len(f1))
		}
		if strings.ContainsAny(f1, ":ABCDEF") {
			t.Fatalf("want lowercase hex without colons: %q", f1)
		}
		if Fingerprint([]byte("other")) == f1 {
			t.Fatal("distinct inputs collided")
		}
	})
}
