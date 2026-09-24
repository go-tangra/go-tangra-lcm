// Command lcm-devca generates a development root CA and per-service SVIDs into
// .dev/ca using the lcm module's own certificate code (internal/csr for SPIFFE
// identity + PEM, the same self-signed-root and leaf shape as internal/ca and
// internal/issue). It is the production-shaped replacement for the throwaway
// cmd/freya-devca: the output layout is identical (<name>.pem, <name>.key,
// ca.pem) so every service's file identity provider reads it unchanged, but the
// trust root is an lcm-issued CA. Offline; needs no running service or database.
//
// WARNING: development only. Never deploy these files.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
)

func main() {
	out := flag.String("out", ".dev/ca", "output directory")
	td := flag.String("trust-domain", "example.org", "trust domain")
	services := flag.String("services", "orders,inventory,billing,auth,gateway,hello,warden,notification,lcm", "comma-separated service names")
	ttl := flag.Duration("ttl", 720*time.Hour, "SVID lifetime (default 30d for development convenience)")
	caTTL := flag.Duration("ca-ttl", 3650*24*time.Hour, "root CA lifetime")
	reuse := flag.Bool("reuse-ca", false, "reuse the existing root CA (ca.pem+ca.key) and only reissue leaves; required for renewal so the trust root stays stable")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o700); err != nil {
		fail(err)
	}
	bundlePath := filepath.Join(*out, "ca.pem")
	keyPath := filepath.Join(*out, "ca.key")

	var root *x509.Certificate
	var rootKey *ecdsa.PrivateKey
	// -reuse-ca keeps the trust root stable across runs (renewal, re-bootstrap):
	// reuse the persisted root when present, otherwise generate and persist it so
	// the first run on a fresh volume also succeeds (idempotent bootstrap).
	if *reuse && fileExists(bundlePath) && fileExists(keyPath) {
		var err error
		if root, rootKey, err = loadRoot(bundlePath, keyPath); err != nil {
			fail(fmt.Errorf("reuse-ca: %w", err))
		}
		fmt.Printf("reusing %s (lcm root CA, spiffe://%s) — reissuing leaves only\n", bundlePath, *td)
	} else {
		var err error
		if root, rootKey, err = generateRoot(*td, *caTTL); err != nil {
			fail(err)
		}
		if err := os.WriteFile(bundlePath, csr.EncodeCertPEM(root.Raw), 0o600); err != nil { // #nosec G306 -- dev CA files
			fail(err)
		}
		rk, err := marshalKey(rootKey)
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(keyPath, rk, 0o600); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s %s (lcm root CA, spiffe://%s)\n", bundlePath, keyPath, *td)
	}

	for _, name := range strings.Split(*services, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		spiffeID := "spiffe://" + *td + "/svc/" + name
		if _, err := csr.ParseSPIFFEID(spiffeID); err != nil {
			fail(fmt.Errorf("%s: %w", name, err))
		}
		leafDER, leafKey, err := issueLeaf(spiffeID, name, *ttl, root, rootKey)
		if err != nil {
			fail(fmt.Errorf("%s: %w", name, err))
		}
		certPath := filepath.Join(*out, name+".pem")
		keyPath := filepath.Join(*out, name+".key")
		if err := os.WriteFile(certPath, csr.EncodeCertPEM(leafDER), 0o600); err != nil { // #nosec G306 -- dev SVID files
			fail(err)
		}
		keyPEM, err := marshalKey(leafKey)
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s %s (%s)\n", certPath, keyPath, spiffeID)
	}
	fmt.Fprintln(os.Stderr, "WARNING: lcm development CA only; never deploy these files")
}

// fileExists reports whether a path exists and is a regular file.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// generateRoot mints a self-signed root CA for the trust domain (same shape as
// internal/ca: ECDSA P-256, CA:true, keyCertSign|cRLSign, URI SAN spiffe://<td>).
func generateRoot(trustDomain string, ttl time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: trustDomain + " LCM Root"},
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: trustDomain}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// issueLeaf mints a service SVID signed by the root (same shape as
// internal/issue: URI SAN = the SPIFFE id, serverAuth|clientAuth).
func issueLeaf(spiffeID, cn string, ttl time.Duration, root *x509.Certificate, rootKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

func marshalKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// loadRoot reads an existing root CA cert + key so renewals reissue leaves
// under the SAME trust root (a fresh root each run would break the mesh).
func loadRoot(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certPath) // #nosec G304 -- operator-supplied dev path
	if err != nil {
		return nil, nil, err
	}
	cblk, _ := pem.Decode(cb)
	if cblk == nil {
		return nil, nil, fmt.Errorf("ca.pem: not PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied dev path
	if err != nil {
		return nil, nil, err
	}
	kblk, _ := pem.Decode(kb)
	if kblk == nil {
		return nil, nil, fmt.Errorf("ca.key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("ca.key: not an ECDSA key")
	}
	return cert, ek, nil
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "lcm-devca:", err)
	os.Exit(1)
}
