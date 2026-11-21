package issue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
)

func TestGenerateKeyHonoursType(t *testing.T) {
	cases := []struct {
		kt    string
		check func(any) bool
	}{
		{KeyTypeECDSAP256, func(k any) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Curve == elliptic.P256() }},
		{KeyTypeECDSAP384, func(k any) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Curve == elliptic.P384() }},
		{KeyTypeRSA2048, func(k any) bool { r, ok := k.(*rsa.PublicKey); return ok && r.N.BitLen() == 2048 }},
		{KeyTypeRSA4096, func(k any) bool { r, ok := k.(*rsa.PublicKey); return ok && r.N.BitLen() == 4096 }},
		{"", func(k any) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Curve == elliptic.P256() }},
	}
	for _, c := range cases {
		k, err := generateKey(c.kt)
		if err != nil {
			t.Fatalf("%q: %v", c.kt, err)
		}
		if !c.check(k.Public()) {
			t.Fatalf("%q: wrong key %T", c.kt, k.Public())
		}
	}
}

func TestIssueGeneratedKeyUsesIssuerKeyType(t *testing.T) {
	f := newFixture(t)
	iv, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "rsa", Type: "self_signed", TrustDomain: "example.org", IsDefault: true, Enabled: true,
		Settings: sealed.Settings{"key_type": KeyTypeRSA2048},
	})
	if err != nil {
		t.Fatalf("CreateIssuer: %v", err)
	}
	b, err := f.svc.Issue(context.Background(), f.admin, IssueInput{
		IssuerID: iv.ID, SpiffeID: "spiffe://example.org/db", DeliverKey: true, ValiditySeconds: 3600,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	block, _ := pem.Decode([]byte(b.KeyPEM))
	if block == nil {
		t.Fatal("key not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if r, ok := k.(*rsa.PrivateKey); !ok || r.N.BitLen() != 2048 {
		t.Fatalf("generated key is %T, want RSA 2048", k)
	}
	cblock, _ := pem.Decode([]byte(b.CertPEM))
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("certificate key is %v, want RSA", cert.PublicKeyAlgorithm)
	}
}

func TestCreateIssuerRefusesUnknownKeyType(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CreateIssuer(context.Background(), f.admin, IssuerInput{
		Name: "bad", Type: "self_signed", TrustDomain: "example.org", Enabled: true,
		Settings: sealed.Settings{"key_type": "rsa-1024"},
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != "key_type" {
		t.Fatalf("want key_type validation error, got %v", err)
	}
}
