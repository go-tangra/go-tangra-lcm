// Package ca is the self-signed certificate authority for a trust domain. It
// generates an ECDSA P-256 root per (tenant, trust domain) on demand, keeps the
// private key sealed at rest (never in any returned value), hands out a signer
// bound to the parsed root certificate for minting leaves, and assembles the
// trust bundle (active plus retiring roots) that relying parties verify against.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/go-freya/freya/services/lcm/internal/csr"
	"github.com/go-freya/freya/services/lcm/internal/repo"
	"github.com/go-freya/freya/services/lcm/internal/sealed"
	"github.com/go-freya/freya/services/lcm/internal/store"
)

// Errors.
var (
	// ErrInput rejects a bad trust domain or tenant before any key is generated.
	ErrInput = errors.New("ca: invalid input")
	// ErrParse reports sealed key or stored certificate material that will not decode.
	ErrParse = errors.New("ca: material could not be parsed")
)

// rootValidity is the lifetime of a generated self-signed root (~10 years).
const rootValidity = 10 * 365 * 24 * time.Hour

// serialBits is the entropy of a certificate serial number.
const serialBits = 128

// randReader is the entropy source; tests replace it to exercise error paths.
var randReader io.Reader = rand.Reader

// These indirections default to the real crypto operations and let tests reach
// generate's defensive error returns. The FIPS 140-3 key generator and signer
// draw their entropy from the approved internal DRBG rather than the reader
// passed in, and marshalling and sealing a freshly minted P-256 key do not fail
// in practice, so a faulty randReader alone cannot exercise those branches.
var (
	generateKey       = ecdsa.GenerateKey
	createCertificate = x509.CreateCertificate
	marshalPrivateKey = x509.MarshalPKCS8PrivateKey
	sealKey           = func(env *sealed.Envelope, plaintext, ad []byte) ([]byte, error) {
		return env.Seal(plaintext, ad)
	}
)

// Repo is the CA persistence the Authority depends on (repo.Store satisfies it).
type Repo interface {
	CAByState(ctx context.Context, tenantID, trustDomain, state string) (store.CA, error)
	CAsForDomain(ctx context.Context, tenantID, trustDomain string) ([]store.CA, error)
	InsertCA(ctx context.Context, c store.CA) error
	Atomic(ctx context.Context, tenantID string, fn func(repo.Store) error) error
}

// Authority mints and rotates the CA material for trust domains.
type Authority struct {
	repo Repo
	env  *sealed.Envelope
	// Clock supplies the current time; tests replace it with a fake clock.
	Clock func() time.Time
}

// New wires the authority over its persistence and sealing envelope.
func New(r Repo, env *sealed.Envelope) *Authority {
	return &Authority{repo: r, env: env, Clock: time.Now}
}

// now reads the (possibly faked) clock, defaulting to time.Now.
func (a *Authority) now() time.Time {
	if a.Clock != nil {
		return a.Clock()
	}
	return time.Now()
}

// validTrustDomain reports whether host is a non-empty run (<=253 bytes) of
// lowercase letters, digits, dots and hyphens.
func validTrustDomain(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
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

// EnsureCA returns the active CA for (tenant, trust domain), generating a
// self-signed root the first time. It is concurrency-safe within a tenant: the
// generation runs under Atomic, re-reads inside the transaction, and on a
// unique-active-CA conflict re-reads and returns the winner.
func (a *Authority) EnsureCA(ctx context.Context, tenantID, trustDomain string) (store.CA, error) {
	if tenantID == "" || !validTrustDomain(trustDomain) {
		return store.CA{}, ErrInput
	}
	existing, err := a.repo.CAByState(ctx, tenantID, trustDomain, "active")
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.CA{}, err
	}
	var out store.CA
	err = a.repo.Atomic(ctx, tenantID, func(tx repo.Store) error {
		if again, rerr := tx.CAByState(ctx, tenantID, trustDomain, "active"); rerr == nil {
			out = again
			return nil
		} else if !errors.Is(rerr, store.ErrNotFound) {
			return rerr
		}
		fresh, gerr := a.generate(tenantID, trustDomain)
		if gerr != nil {
			return gerr
		}
		if ierr := tx.InsertCA(ctx, fresh); ierr != nil {
			if errors.Is(ierr, store.ErrConflict) {
				won, rerr := tx.CAByState(ctx, tenantID, trustDomain, "active")
				if rerr != nil {
					return rerr
				}
				out = won
				return nil
			}
			return ierr
		}
		out = fresh
		return nil
	})
	if err != nil {
		return store.CA{}, err
	}
	return out, nil
}

// generate builds and seals a fresh self-signed root for the trust domain.
func (a *Authority) generate(tenantID, trustDomain string) (store.CA, error) {
	id := store.NewID()
	priv, err := generateKey(elliptic.P256(), randReader)
	if err != nil {
		return store.CA{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return store.CA{}, err
	}
	uri, err := url.Parse("spiffe://" + trustDomain)
	if err != nil {
		return store.CA{}, ErrInput
	}
	now := a.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: trustDomain + " LCM Root"},
		NotBefore:             now,
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		URIs:                  []*url.URL{uri},
	}
	der, err := createCertificate(randReader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return store.CA{}, err
	}
	keyDER, err := marshalPrivateKey(priv)
	if err != nil {
		return store.CA{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	blob, err := sealKey(a.env, keyPEM, sealed.ADCA(id))
	if err != nil {
		return store.CA{}, err
	}
	return store.CA{
		ID:          id,
		TenantID:    tenantID,
		TrustDomain: trustDomain,
		CertPEM:     string(csr.EncodeCertPEM(der)),
		KeySealed:   blob,
		State:       "active",
		NotBefore:   tmpl.NotBefore,
		NotAfter:    tmpl.NotAfter,
		Serial:      serial.String(),
	}, nil
}

// Signer opens the sealed CA key and parses the CA certificate, returning a
// signer and the parsed root usable to sign leaves. The private key is never
// exposed beyond the returned crypto.Signer.
func (a *Authority) Signer(_ context.Context, ca store.CA) (crypto.Signer, *x509.Certificate, error) {
	keyPEM, err := a.env.Open(ca.KeySealed, sealed.ADCA(ca.ID))
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, ErrParse
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, ErrParse
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, ErrParse
	}
	certBlock, _ := pem.Decode([]byte(ca.CertPEM))
	if certBlock == nil {
		return nil, nil, ErrParse
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, ErrParse
	}
	return signer, cert, nil
}

// Bundle returns the PEM trust bundle for the trust domain: the active root and
// any retiring roots, so verifiers accept certificates during a rotation. The
// "next" (not yet active) root is excluded.
func (a *Authority) Bundle(ctx context.Context, tenantID, trustDomain string) (string, error) {
	cas, err := a.repo.CAsForDomain(ctx, tenantID, trustDomain)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range cas {
		if c.State == "active" || c.State == "retiring" {
			b.WriteString(c.CertPEM)
		}
	}
	return b.String(), nil
}

// SignLeaf mints a short-lived leaf certificate for spiffeID under the
// (tenant, trustDomain) root, signing the caller-supplied public key. It is the
// bootstrap primitive: lcm self-issues its own SVID with it, and the lcmsvc
// bootstrap subcommand mints sibling service SVIDs with it, so the whole mesh
// chains to the one DB-sealed root. No issued_certificate row is written (there
// is no requesting subject); revocation/lifecycle tracking belongs to the
// Issue/Enroll path, not to bootstrap. The private key never reaches lcm — only
// the public key is signed.
func (a *Authority) SignLeaf(ctx context.Context, tenantID, trustDomain, spiffeID string, pub crypto.PublicKey, ttl time.Duration) (leafDER []byte, notAfter time.Time, err error) {
	if ttl <= 0 {
		return nil, time.Time{}, ErrInput
	}
	sid, perr := csr.ParseSPIFFEID(spiffeID)
	if perr != nil || sid.TrustDomain != trustDomain {
		return nil, time.Time{}, ErrInput
	}
	caRow, err := a.EnsureCA(ctx, tenantID, trustDomain)
	if err != nil {
		return nil, time.Time{}, err
	}
	signer, caCert, err := a.Signer(ctx, caRow)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	uri, err := url.Parse(sid.String())
	if err != nil {
		return nil, time.Time{}, ErrInput
	}
	now := a.now()
	notAfter = now.Add(ttl)
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: sid.String()},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := createCertificate(randReader, leaf, caCert, pub, signer)
	if err != nil {
		return nil, time.Time{}, err
	}
	return der, notAfter, nil
}

// randomSerial returns a positive 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	n, err := rand.Int(randReader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}
