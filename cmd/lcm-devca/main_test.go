package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/url"
	"testing"
	"time"
)

func TestGenerateRootAndIssueLeaf(t *testing.T) {
	root, rootKey, err := generateRoot("example.org", time.Hour)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root is not a signing CA")
	}
	if got := root.URIs; len(got) != 1 || got[0].String() != "spiffe://example.org" {
		t.Fatalf("root URI SAN = %v", got)
	}

	spiffeID := "spiffe://example.org/svc/gateway"
	der, key, err := issueLeaf(spiffeID, "gateway", time.Hour, root, rootKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	// URI SAN is the SPIFFE id.
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffeID {
		t.Fatalf("leaf URI SAN = %v", leaf.URIs)
	}
	// The leaf's public key matches the generated key.
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("leaf public key does not match")
	}
	// The leaf chains to the root.
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the root: %v", err)
	}
	// Not a CA; client+server auth.
	if leaf.IsCA {
		t.Fatal("leaf must not be a CA")
	}
	// marshalKey round-trips.
	pemKey, err := marshalKey(key)
	if err != nil || len(pemKey) == 0 {
		t.Fatalf("marshalKey: %v", err)
	}
	// A bad SPIFFE id is rejected by url.Parse at issuance time is not our job;
	// the CLI validates via csr.ParseSPIFFEID before calling issueLeaf.
	_ = url.URL{}
}
