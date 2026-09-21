// Package lcmidentity is a Freya identity.Provider that obtains a service's
// SVID by enrolling with the running lcm certificate authority and keeps it
// fresh with lcm's live Agent.Watch stream. It is injected into a service with
// freya.WithIdentityProvider, so the framework never depends on the lcm module.
//
// The private key is generated locally and never leaves the workload: the
// provider signs a CSR bound to its SPIFFE id and lcm signs it. The provider
// also satisfies the framework's structural credential source
// (Credential() (*tls.Certificate, error)) so transport can obtain key
// material without importing anything from lcm.
package lcmidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/services/lcm/pkg/lcmclient"
)

// Config configures the enrollment provider.
type Config struct {
	// Conn is an established connection to the lcm gRPC endpoint. The caller
	// dials it with a bootstrap TLS config that trusts lcm's root (server auth).
	Conn grpc.ClientConnInterface
	// TenantID the workload belongs to.
	TenantID string
	// TrustDomain and ServiceName form the requested SPIFFE id
	// spiffe://<TrustDomain>/svc/<ServiceName>.
	TrustDomain string
	ServiceName string
	// EnrollmentToken authorises a first enrollment without a prior identity
	// (auth-minted); empty enrolls with the caller's own identity.
	EnrollmentToken string
	// RenewBefore renews this long before expiry (default 1/3 of the lifetime).
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

// Provider enrolls with lcm and renews via its Agent stream.
type Provider struct {
	cfg    Config
	client *lcmclient.Client
	now    func() time.Time

	mu    sync.RWMutex
	st    *state
	ver   uint64
	subs  []chan identity.Update
	close chan struct{}
	once  sync.Once
}

// Compile-time: Provider is an identity.Provider and a structural credential
// source (Credential is asserted by transport/tlsconf via internal cred.Source).
var _ identity.Provider = (*Provider)(nil)

// New enrolls for an initial SVID and returns a ready provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Conn == nil {
		return nil, errors.New("lcmidentity: Conn is required")
	}
	if cfg.TrustDomain == "" || cfg.ServiceName == "" || cfg.TenantID == "" {
		return nil, errors.New("lcmidentity: TenantID, TrustDomain and ServiceName are required")
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	p := &Provider{cfg: cfg, client: lcmclient.New(cfg.Conn), now: cfg.now, close: make(chan struct{})}
	st, err := p.enroll(ctx)
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

// enroll generates a fresh key + CSR and asks lcm to sign it.
func (p *Provider) enroll(ctx context.Context) (*state, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrPEM, err := makeCSR(p.cfg.spiffeID(), key)
	if err != nil {
		return nil, err
	}
	b, err := p.client.Enroll(ctx, lcmclient.EnrollRequest{
		TenantID: p.cfg.TenantID, SpiffeID: p.cfg.spiffeID(), CSRPEM: string(csrPEM), EnrollmentToken: p.cfg.EnrollmentToken,
	})
	if err != nil {
		return nil, fmt.Errorf("lcmidentity: enroll: %w", err)
	}
	return p.buildState(b, key)
}

func (p *Provider) buildState(b *lcmclient.Bundle, key *ecdsa.PrivateKey) (*state, error) {
	certDERs, err := decodeCerts(b.CertPEM)
	if err != nil || len(certDERs) == 0 {
		return nil, fmt.Errorf("lcmidentity: certificate: %w", err)
	}
	chainDERs, _ := decodeCerts(b.ChainPEM)
	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return nil, fmt.Errorf("lcmidentity: leaf: %w", err)
	}
	roots, err := decodeCertsParsed(b.BundlePEM)
	if err != nil || len(roots) == 0 {
		return nil, errors.New("lcmidentity: empty trust bundle")
	}
	sid, err := identity.NewSPIFFEID(p.cfg.TrustDomain, p.cfg.ServiceName)
	if err != nil {
		return nil, err
	}
	crt := tls.Certificate{Certificate: append(certDERs, chainDERs...), PrivateKey: key, Leaf: leaf}
	return &state{
		crt:    crt,
		id:     ident{id: sid, nb: leaf.NotBefore, na: leaf.NotAfter, serial: leaf.SerialNumber.String()},
		bundle: bundle{td: p.cfg.TrustDomain, roots: roots},
	}, nil
}

// Current returns the current identity and trust bundle.
func (p *Provider) Current(context.Context) (identity.Identity, identity.Bundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, nil, errors.New("lcmidentity: no identity")
	}
	return p.st.id, p.st.bundle, nil
}

// Credential returns the current key pair (structural cred.Source; used by
// transport/tlsconf). Not part of identity.Provider.
func (p *Provider) Credential() (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, errors.New("lcmidentity: no credential")
	}
	c := p.st.crt
	return &c, nil
}

// Watch renews the SVID before expiry and whenever lcm streams an update for
// it, delivering an identity.Update on each change.
func (p *Provider) Watch(ctx context.Context) (<-chan identity.Update, error) {
	ch := make(chan identity.Update, 1)
	p.mu.Lock()
	p.subs = append(p.subs, ch)
	p.mu.Unlock()
	go p.run(ctx, ch)
	return ch, nil
}

func (p *Provider) run(ctx context.Context, ch chan identity.Update) {
	// Live stream from lcm pokes an out-of-band renewal on any update for us.
	poke := make(chan struct{}, 1)
	go func() {
		_ = p.client.WatchTenant(ctx, p.cfg.TenantID, "", func(u lcmclient.Update) {
			if u.SpiffeID == "" || u.SpiffeID == p.cfg.spiffeID() {
				select {
				case poke <- struct{}{}:
				default:
				}
			}
		})
	}()
	for {
		p.mu.RLock()
		na := p.st.id.na
		p.mu.RUnlock()
		d := p.renewBefore(na)
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.close:
			timer.Stop()
			return
		case <-timer.C:
		case <-poke:
			timer.Stop()
		}
		st, err := p.enroll(ctx)
		if err != nil {
			select {
			case ch <- identity.Update{Err: err}:
			default:
			}
			// back off a little before retrying
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
		p.ver++
		st.bundle.ver = p.ver
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
		p.mu.RLock()
		life := p.st.id.na.Sub(p.st.id.nb)
		p.mu.RUnlock()
		rb = life / 3
	}
	d := time.Until(notAfter) - rb
	if p.cfg.now != nil {
		d = notAfter.Sub(p.now()) - rb
	}
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

// makeCSR builds a CSR bound to the SPIFFE id (URI SAN), signed by key.
func makeCSR(spiffeID string, key *ecdsa.PrivateKey) ([]byte, error) {
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{uri}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func decodeCerts(pemBytes string) ([][]byte, error) {
	var out [][]byte
	rest := []byte(pemBytes)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
	}
	return out, nil
}

func decodeCertsParsed(pemBytes string) ([]*x509.Certificate, error) {
	ders, _ := decodeCerts(pemBytes)
	var out []*x509.Certificate
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
