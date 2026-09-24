// Package selfidentity is a Freya identity.Provider that lets lcm bootstrap its
// OWN SVID directly from its DB-sealed CA, with no external cert file. It mints
// spiffe://<trust-domain>/svc/<service> against the same root the CA issues
// every other workload from, so the whole mesh chains to ONE trust root. It is
// injected via freya.WithIdentityProvider; the private key is generated locally
// and never persisted. It also satisfies the framework's structural credential
// source (Credential() (*tls.Certificate, error)) so transport/tlsconf can
// obtain key material without importing lcm.
package selfidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra/v4/identity"
)

// CA is the subset of *ca.Authority this provider needs. *ca.Authority
// satisfies it; a fake satisfies it in tests.
type CA interface {
	SignLeaf(ctx context.Context, tenantID, trustDomain, spiffeID string, pub crypto.PublicKey, ttl time.Duration) (leafDER []byte, notAfter time.Time, err error)
	Bundle(ctx context.Context, tenantID, trustDomain string) (string, error)
}

// Config configures the self-issue provider.
type Config struct {
	CA          CA
	TenantID    string
	TrustDomain string
	ServiceName string
	// TTL is the lifetime of each self-issued leaf.
	TTL time.Duration
	// RenewBefore renews this long before expiry (default 1/3 of TTL).
	RenewBefore time.Duration
	// now is overridable in tests.
	now func() time.Time
}

func (c Config) spiffeID() string {
	return "spiffe://" + c.TrustDomain + "/svc/" + c.ServiceName
}

type ident struct {
	id     identity.SPIFFEID
	nb, na time.Time
	serial string
}

func (i ident) ID() identity.SPIFFEID { return i.id }
func (i ident) NotBefore() time.Time  { return i.nb }
func (i ident) NotAfter() time.Time   { return i.na }
func (i ident) Serial() string        { return i.serial }

type bundle struct {
	td    string
	roots []*x509.Certificate
	ver   uint64
}

func (b bundle) TrustDomain() string        { return b.td }
func (b bundle) Roots() []*x509.Certificate { return b.roots }
func (b bundle) Version() uint64            { return b.ver }

type state struct {
	crt    tls.Certificate
	id     ident
	bundle bundle
}

// Provider self-issues its SVID from the CA and re-mints before expiry.
type Provider struct {
	cfg Config
	now func() time.Time

	mu    sync.RWMutex
	st    *state
	ver   uint64
	subs  []chan identity.Update
	close chan struct{}
	once  sync.Once
}

// Compile-time: Provider is an identity.Provider. It also structurally
// satisfies transport/tlsconf's credential source via Credential().
var _ identity.Provider = (*Provider)(nil)

// New mints an initial SVID and returns a ready provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.CA == nil {
		return nil, errors.New("selfidentity: CA is required")
	}
	if cfg.TenantID == "" || cfg.TrustDomain == "" || cfg.ServiceName == "" {
		return nil, errors.New("selfidentity: TenantID, TrustDomain and ServiceName are required")
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("selfidentity: TTL must be positive")
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	p := &Provider{cfg: cfg, now: cfg.now, close: make(chan struct{})}
	st, err := p.mint(ctx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.ver++
	st.bundle.ver = p.ver
	p.st = st
	p.mu.Unlock()
	return p, nil
}

// mint generates a fresh key and self-issues a leaf from the CA.
func (p *Provider) mint(ctx context.Context) (*state, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _, err := p.cfg.CA.SignLeaf(ctx, p.cfg.TenantID, p.cfg.TrustDomain, p.cfg.spiffeID(), &key.PublicKey, p.cfg.TTL)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	bundlePEM, err := p.cfg.CA.Bundle(ctx, p.cfg.TenantID, p.cfg.TrustDomain)
	if err != nil {
		return nil, err
	}
	roots, err := parseRoots(bundlePEM)
	if err != nil || len(roots) == 0 {
		return nil, errors.New("selfidentity: empty trust bundle")
	}
	sid, err := identity.NewSPIFFEID(p.cfg.TrustDomain, p.cfg.ServiceName)
	if err != nil {
		return nil, err
	}
	return &state{
		crt:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		id:     ident{id: sid, nb: leaf.NotBefore, na: leaf.NotAfter, serial: leaf.SerialNumber.String()},
		bundle: bundle{td: p.cfg.TrustDomain, roots: roots},
	}, nil
}

// Current returns the current identity and trust bundle.
func (p *Provider) Current(context.Context) (identity.Identity, identity.Bundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, nil, errors.New("selfidentity: no identity")
	}
	return p.st.id, p.st.bundle, nil
}

// Credential returns the current key pair (structural cred.Source; used by
// transport/tlsconf). Not part of identity.Provider.
func (p *Provider) Credential() (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, errors.New("selfidentity: no credential")
	}
	c := p.st.crt
	return &c, nil
}

// Watch re-mints the SVID before expiry, delivering an identity.Update on each
// change.
func (p *Provider) Watch(ctx context.Context) (<-chan identity.Update, error) {
	ch := make(chan identity.Update, 1)
	p.mu.Lock()
	p.subs = append(p.subs, ch)
	p.mu.Unlock()
	go p.run(ctx, ch)
	return ch, nil
}

func (p *Provider) run(ctx context.Context, ch chan identity.Update) {
	for {
		p.mu.RLock()
		na := p.st.id.na
		p.mu.RUnlock()
		timer := time.NewTimer(p.renewBefore(na))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.close:
			timer.Stop()
			return
		case <-timer.C:
		}
		st, err := p.mint(ctx)
		if err != nil {
			select {
			case ch <- identity.Update{Err: err}:
			default:
			}
			select {
			case <-ctx.Done():
				return
			case <-p.close:
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		p.mu.Lock()
		// Only bump the trust-bundle version when the ROOT SET actually changes.
		// A pure leaf renewal keeps the same version, so the framework treats it
		// as a leaf rotation (non-disruptive) instead of a bundle change — the
		// latter drains the outbound gRPC pool (Pool.Rotate) and would drop this
		// service's gateway registration and auth verifier connections.
		if sameRoots(p.st.bundle.roots, st.bundle.roots) {
			st.bundle.ver = p.st.bundle.ver
		} else {
			p.ver++
			st.bundle.ver = p.ver
		}
		p.st = st
		p.mu.Unlock()
		select {
		case ch <- identity.Update{Identity: st.id, Bundle: st.bundle}:
		default:
		}
	}
}

func (p *Provider) renewBefore(notAfter time.Time) time.Duration {
	rb := p.cfg.RenewBefore
	if rb <= 0 {
		rb = p.cfg.TTL / 3
	}
	d := notAfter.Sub(p.now()) - rb
	if d < 0 {
		d = 0
	}
	return d
}

// Close stops renewal.
func (p *Provider) Close() error {
	p.once.Do(func() { close(p.close) })
	return nil
}

// sameRoots reports whether two root sets contain the same certificates
// (by raw DER), regardless of order. A self-issue renewal re-fetches the same
// DB-sealed root, so this is true on every ordinary renewal.
func sameRoots(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, c := range a {
		seen[string(c.Raw)]++
	}
	for _, c := range b {
		if seen[string(c.Raw)] == 0 {
			return false
		}
		seen[string(c.Raw)]--
	}
	return true
}

func parseRoots(pemStr string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemStr)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
