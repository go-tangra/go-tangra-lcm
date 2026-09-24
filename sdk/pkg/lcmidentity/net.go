package lcmidentity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/lcmclient"
	"github.com/go-tangra/go-tangra/v4/identity"
)

// NetConfig configures a network enrollment provider: a workload obtains its
// FIRST SVID keylessly over lcm's public HTTP enroll route (authenticated by a
// single-use join token), then RENEWS over a direct mTLS gRPC channel to lcm
// presenting the SVID it just received (no token). The private key is generated
// locally and never leaves the workload.
type NetConfig struct {
	// EnrollURL is the public first-enroll endpoint, e.g.
	// https://gateway:8443/api/lcm/v1/enroll (server-auth TLS; no client cert).
	EnrollURL string
	// LCMGRPCTarget is lcm's gRPC endpoint for renewal (direct mTLS), e.g. lcm:9945.
	LCMGRPCTarget string
	TenantID      string
	TrustDomain   string
	ServiceName   string
	// EnrollmentToken authorises the FIRST enroll only (single-use).
	EnrollmentToken string
	// RenewBefore renews this long before expiry (default 1/3 of the lifetime).
	RenewBefore time.Duration
	// EnrollTLS, if set, is the client TLS configuration of the first-enroll
	// HTTPS call (cloned). Use it to verify lcm's keyless enroll listener, which
	// presents lcm's SVID (no DNS name, mesh root): build it with the
	// framework's tlsconf.LoadEnrollClientConfig (enroll.ca_file +
	// enroll.server_spiffe_id). Nil: system roots + the host name of EnrollURL
	// (enrolling through the gateway edge). Excludes Insecure.
	EnrollTLS *tls.Config
	// Insecure skips SERVER verification on the first-enroll HTTP call only
	// (development). Renewals are always verified against the mesh bundle.
	Insecure bool
	// StateFile, if set, persists the SVID (cert+key+bundle) so a restart reuses
	// it and renews over mTLS instead of consuming a fresh (single-use) join
	// token. The join token is then only needed for the very first enroll.
	StateFile string
	now       func() time.Time
}

func (c NetConfig) spiffeID() string {
	return "spiffe://" + c.TrustDomain + "/svc/" + c.ServiceName
}

// NetProvider enrolls over the network and keeps the SVID fresh.
type NetProvider struct {
	cfg  NetConfig
	now  func() time.Time
	http *http.Client

	mu        sync.RWMutex
	st        *state
	ver       uint64
	firstDone bool
	renewConn *grpc.ClientConn
	subs      []chan identity.Update
	close     chan struct{}
	once      sync.Once
}

var _ identity.Provider = (*NetProvider)(nil)

// NewNet enrolls for an initial SVID over HTTP and returns a ready provider.
func NewNet(ctx context.Context, cfg NetConfig) (*NetProvider, error) {
	if cfg.EnrollURL == "" || cfg.LCMGRPCTarget == "" {
		return nil, errors.New("lcmidentity: EnrollURL and LCMGRPCTarget are required")
	}
	if cfg.TrustDomain == "" || cfg.ServiceName == "" {
		return nil, errors.New("lcmidentity: TrustDomain and ServiceName are required")
	}
	if cfg.EnrollmentToken == "" {
		return nil, errors.New("lcmidentity: an enrollment token is required for the first enroll")
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.Insecure && cfg.EnrollTLS != nil {
		return nil, errors.New("lcmidentity: EnrollTLS and Insecure are mutually exclusive")
	}
	tr := &http.Transport{}
	switch {
	case cfg.EnrollTLS != nil:
		tr.TLSClientConfig = cfg.EnrollTLS.Clone()
	case cfg.Insecure:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 -- dev self-signed edge; client is not yet identified
	}
	p := &NetProvider{cfg: cfg, now: cfg.now, http: &http.Client{Transport: tr, Timeout: 20 * time.Second}, close: make(chan struct{})}
	// Reuse a persisted, still-valid SVID across restarts: skip the single-use
	// join token and renew over mTLS instead. Only a cold start (no valid state)
	// consumes the token.
	if st := p.loadPersisted(); st != nil {
		p.mu.Lock()
		p.ver++
		st.bundle.ver = p.ver
		p.st, p.firstDone = st, true
		p.mu.Unlock()
		return p, nil
	}
	// The first enroll can race lcm's gateway registration on a cold stack;
	// retry with backoff so bootstrap is robust.
	var st *state
	var err error
	for attempt := 0; ; attempt++ {
		if st, err = p.mint(ctx); err == nil {
			break
		}
		if attempt >= 20 || ctx.Err() != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	p.mu.Lock()
	p.ver++
	st.bundle.ver = p.ver
	p.st = st
	p.firstDone = true
	p.mu.Unlock()
	p.persist(st)
	return p, nil
}

// mint generates a fresh key + CSR and obtains a signed SVID: the first time
// over the public HTTP enroll route with the join token, thereafter over the
// direct mTLS gRPC channel presenting the current SVID (no token).
func (p *NetProvider) mint(ctx context.Context) (*state, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrPEM, err := makeCSR(p.cfg.spiffeID(), key)
	if err != nil {
		return nil, err
	}
	p.mu.RLock()
	first := !p.firstDone
	p.mu.RUnlock()

	var b *lcmclient.Bundle
	if first {
		b, err = p.enrollHTTP(ctx, string(csrPEM))
	} else {
		b, err = p.renewMTLS(ctx, string(csrPEM))
	}
	if err != nil {
		return nil, err
	}
	return buildStateFrom(p.cfg.TrustDomain, p.cfg.ServiceName, b, key)
}

// enrollHTTP performs the keyless first enroll over the public HTTP route.
func (p *NetProvider) enrollHTTP(ctx context.Context, csrPEM string) (*lcmclient.Bundle, error) {
	body, _ := json.Marshal(map[string]string{"spiffe_id": p.cfg.spiffeID(), "csr_pem": csrPEM, "enrollment_token": p.cfg.EnrollmentToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.EnrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lcmidentity: enroll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lcmidentity: enroll: http %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		CertPEM   string `json:"cert_pem"`
		ChainPEM  string `json:"chain_pem"`
		BundlePEM string `json:"bundle_pem"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("lcmidentity: enroll response: %w", err)
	}
	return &lcmclient.Bundle{CertPEM: out.CertPEM, ChainPEM: out.ChainPEM, BundlePEM: out.BundlePEM}, nil
}

// renewMTLS renews over a direct mTLS gRPC channel to lcm, presenting the
// current SVID as the client certificate and enrolling with no token (the
// caller-identity route: lcm issues for the peer's own SPIFFE id).
func (p *NetProvider) renewMTLS(ctx context.Context, csrPEM string) (*lcmclient.Bundle, error) {
	conn, err := p.mtlsConn()
	if err != nil {
		return nil, err
	}
	return lcmclient.New(conn).Enroll(ctx, lcmclient.EnrollRequest{TenantID: p.cfg.TenantID, SpiffeID: p.cfg.spiffeID(), CSRPEM: csrPEM})
}

// mtlsConn lazily builds the renewal connection; its client-certificate
// callback returns the CURRENT SVID on every handshake, so the connection keeps
// working across rotations.
func (p *NetProvider) mtlsConn() (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.renewConn != nil {
		return p.renewConn, nil
	}
	tlsCfg := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return p.credential() },
		// We verify lcm's server SVID ourselves (SPIFFE URI SAN, not DNS), so we
		// disable Go's default hostname check and chain-verify against the mesh
		// bundle we hold. This is NOT weakened by cfg.Insecure: once enrolled the
		// workload has real trust, so the renewal channel is always authenticated
		// both ways.
		InsecureSkipVerify:    true,              // #nosec G402 -- replaced by VerifyPeerCertificate below (SPIFFE-aware)
		VerifyPeerCertificate: p.verifyLCMServer, // #nosec G123 -- client config without a ClientSessionCache: no session resumption, every handshake runs the verifier
		MinVersion:            tls.VersionTLS13,
	}
	conn, err := grpc.NewClient(p.cfg.LCMGRPCTarget, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	p.renewConn = conn
	return conn, nil
}

// verifyLCMServer chain-verifies lcm's presented server certificate against the
// mesh roots the workload currently holds and checks its SPIFFE id is svc/lcm.
func (p *NetProvider) verifyLCMServer(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("lcmidentity: lcm presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, d := range rawCerts[1:] {
		if c, cerr := x509.ParseCertificate(d); cerr == nil {
			inter.AddCert(c)
		}
	}
	p.mu.RLock()
	roots := x509.NewCertPool()
	if p.st != nil {
		for _, r := range p.st.bundle.roots {
			roots.AddCert(r)
		}
	}
	p.mu.RUnlock()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: p.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("lcmidentity: lcm server not trusted: %w", err)
	}
	want := "spiffe://" + p.cfg.TrustDomain + "/svc/lcm"
	for _, u := range leaf.URIs {
		if u.String() == want {
			return nil
		}
	}
	return errors.New("lcmidentity: lcm server SPIFFE id mismatch")
}

func (p *NetProvider) credential() (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, errors.New("lcmidentity: no credential")
	}
	c := p.st.crt
	return &c, nil
}

// Current returns the current identity and trust bundle.
func (p *NetProvider) Current(context.Context) (identity.Identity, identity.Bundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, nil, errors.New("lcmidentity: no identity")
	}
	return p.st.id, p.st.bundle, nil
}

// Credential returns the current key pair (structural cred.Source).
func (p *NetProvider) Credential() (*tls.Certificate, error) { return p.credential() }

// Watch renews before expiry, delivering an identity.Update on each change.
func (p *NetProvider) Watch(ctx context.Context) (<-chan identity.Update, error) {
	ch := make(chan identity.Update, 1)
	p.mu.Lock()
	p.subs = append(p.subs, ch)
	p.mu.Unlock()
	go p.run(ctx, ch)
	return ch, nil
}

func (p *NetProvider) run(ctx context.Context, ch chan identity.Update) {
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
			case <-time.After(5 * time.Second):
			}
			continue
		}
		p.mu.Lock()
		p.ver++
		st.bundle.ver = p.ver
		p.st = st
		p.mu.Unlock()
		p.persist(st)
		select {
		case ch <- identity.Update{Identity: st.id, Bundle: st.bundle}:
		default:
		}
	}
}

func (p *NetProvider) renewBefore(notAfter time.Time) time.Duration {
	rb := p.cfg.RenewBefore
	if rb <= 0 {
		p.mu.RLock()
		life := p.st.id.na.Sub(p.st.id.nb)
		p.mu.RUnlock()
		rb = life / 3
	}
	d := notAfter.Sub(p.now()) - rb
	if d < 0 {
		d = 0
	}
	return d
}

// Close stops renewal and releases the renewal connection.
func (p *NetProvider) Close() error {
	p.once.Do(func() {
		close(p.close)
		p.mu.Lock()
		if p.renewConn != nil {
			_ = p.renewConn.Close()
		}
		p.mu.Unlock()
	})
	return nil
}

// persistedSVID is the on-disk state (all PEM; the key is 0600-guarded).
type persistedSVID struct {
	CertPEM   string `json:"cert_pem"`
	ChainPEM  string `json:"chain_pem"`
	KeyPEM    string `json:"key_pem"`
	BundlePEM string `json:"bundle_pem"`
}

// persist writes the current SVID to StateFile (best-effort, 0600).
func (p *NetProvider) persist(st *state) {
	if p.cfg.StateFile == "" || st == nil {
		return
	}
	key, ok := st.crt.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	rec := persistedSVID{
		CertPEM:   pemBlocks("CERTIFICATE", st.crt.Certificate[:1]),
		ChainPEM:  pemBlocks("CERTIFICATE", st.crt.Certificate[1:]),
		KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		BundlePEM: pemBlocks("CERTIFICATE", rootsDER(st.bundle.roots)),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	tmp := p.cfg.StateFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil { // #nosec G306 -- 0600
		_ = os.Rename(tmp, p.cfg.StateFile)
	}
}

// loadPersisted returns a still-valid persisted SVID, or nil.
func (p *NetProvider) loadPersisted() *state {
	if p.cfg.StateFile == "" {
		return nil
	}
	b, err := os.ReadFile(p.cfg.StateFile)
	if err != nil {
		return nil
	}
	var rec persistedSVID
	if json.Unmarshal(b, &rec) != nil {
		return nil
	}
	key, err := parseECKey(rec.KeyPEM)
	if err != nil {
		return nil
	}
	st, err := buildStateFrom(p.cfg.TrustDomain, p.cfg.ServiceName, &lcmclient.Bundle{CertPEM: rec.CertPEM, ChainPEM: rec.ChainPEM, BundlePEM: rec.BundlePEM}, key)
	if err != nil {
		return nil
	}
	// Reject an expired (or nearly-expired) persisted SVID: fall back to a token
	// enroll instead of serving a dead cert.
	if st.id.na.Sub(p.now()) < time.Minute {
		return nil
	}
	return st
}

func pemBlocks(typ string, ders [][]byte) string {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: d})...)
	}
	return string(out)
}

func rootsDER(roots []*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(roots))
	for _, r := range roots {
		out = append(out, r.Raw)
	}
	return out
}

func parseECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, errors.New("lcmidentity: no key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("lcmidentity: not an EC key")
	}
	return ec, nil
}

// buildStateFrom assembles provider state from a signed bundle + local key.
func buildStateFrom(trustDomain, serviceName string, b *lcmclient.Bundle, key *ecdsa.PrivateKey) (*state, error) {
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
	sid, err := identity.NewSPIFFEID(trustDomain, serviceName)
	if err != nil {
		return nil, err
	}
	return &state{
		crt:    tls.Certificate{Certificate: append(certDERs, chainDERs...), PrivateKey: key, Leaf: leaf},
		id:     ident{id: sid, nb: leaf.NotBefore, na: leaf.NotAfter, serial: leaf.SerialNumber.String()},
		bundle: bundle{td: trustDomain, roots: roots},
	}, nil
}
