package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Bounds on an issuance flow. These cap how much untrusted input the order flow
// will act on regardless of what the caller passes.
const (
	// MaxDomains bounds the identifiers in a single order.
	MaxDomains = 100
	// MaxCSRBytes bounds the DER CSR handed to Obtain.
	MaxCSRBytes = 64 << 10
	// DefaultPollInterval is the WaitAuthorization/WaitOrder poll cadence when
	// Config.PollInterval is zero.
	DefaultPollInterval = 2 * time.Second
	// DefaultTimeout bounds a whole Obtain call when Config.Timeout is zero.
	DefaultTimeout = 5 * time.Minute
)

// Sentinel errors. None of these ever carry an account key, a credential value
// or a DNS AUTH exchange: they name the phase that failed, not the secret.

var (
	ErrConfig              = errors.New("acme: invalid client configuration")
	ErrOrder               = errors.New("acme: order failed")
	ErrChallenge           = errors.New("acme: dns-01 challenge failed")
	ErrProvider            = errors.New("acme: dns provider failed")
	ErrUnsupportedProvider = errors.New("acme: unsupported dns provider")
	ErrTimeout             = errors.New("acme: issuance timed out")
)

// Config configures a Client. AccountKey and DNS are required; the caller owns
// the account key (loaded unsealed from storage) and the DNS provider (built
// from sealed credentials) and passes them in — nothing here is persisted.
type Config struct {
	// DirectoryURL is the ACME directory endpoint. Empty means Let's Encrypt
	// production (via golang.org/x/crypto/acme's default).
	DirectoryURL string
	// AccountEmail is the optional contact for the ACME account.
	AccountEmail string
	// AccountKey signs ACME requests (ECDSA or RSA). See GenerateAccountKey.
	AccountKey crypto.Signer
	// DNS publishes and removes the DNS-01 TXT records.
	DNS DNSProvider
	// AllowInsecure disables TLS verification of the ACME server. It is honoured
	// only for local development against Pebble and must never be set in
	// production. New refuses AllowInsecure against a non-loopback directory.
	AllowInsecure bool
	// EABKeyID and EABHMACKey configure optional External Account Binding: some
	// CAs (ZeroSSL, Google, Sectigo) require the ACME account to be bound to an
	// existing external account with a key identifier and a base64url-decoded
	// HMAC key. Both empty means no EAB.
	EABKeyID   string
	EABHMACKey []byte
	// PollInterval is the authorization/order poll cadence (default 2s).
	PollInterval time.Duration
	// Timeout bounds a whole Obtain call (default 5m).
	Timeout time.Duration
}

// dns01Record and createOrderCert are indirections over the ACME client so
// tests can reach Obtain's defensive error returns: DNS01ChallengeRecord only
// fails for key types the signing path already rejects, and CreateOrderCert
// never returns an empty chain without also returning an error. They default to
// the real methods and behave identically in production.
var (
	dns01Record     = (*xacme.Client).DNS01ChallengeRecord
	createOrderCert = (*xacme.Client).CreateOrderCert
)

// Client issues certificates via ACME DNS-01. It wraps a configured
// golang.org/x/crypto/acme.Client and a DNS provider.
type Client struct {
	ac      *xacme.Client
	dns     DNSProvider
	eabKID  string
	eabHMAC []byte
	email   string
	poll    time.Duration
	limit   time.Duration
}

// New validates cfg and builds a Client. It constructs an
// acme.Client{Key, DirectoryURL} with an http.Client whose transport verifies
// the ACME server's TLS unless AllowInsecure is set for a loopback directory
// (dev/Pebble only). It never logs the account key.
func New(cfg Config) (*Client, error) {
	if cfg.AccountKey == nil || cfg.DNS == nil {
		return nil, ErrConfig
	}
	if cfg.AllowInsecure && !isLoopbackDirectory(cfg.DirectoryURL) {
		// Refuse to skip verification against anything but localhost/Pebble.
		return nil, ErrConfig
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if cfg.AllowInsecure {
		transport.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- loopback Pebble only, guarded above
	}
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	limit := cfg.Timeout
	if limit <= 0 {
		limit = DefaultTimeout
	}
	return &Client{
		ac: &xacme.Client{
			Key:          cfg.AccountKey,
			DirectoryURL: cfg.DirectoryURL,
			HTTPClient:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
		},
		dns:     cfg.DNS,
		eabKID:  cfg.EABKeyID,
		eabHMAC: cfg.EABHMACKey,
		email:   cfg.AccountEmail,
		poll:    poll,
		limit:   limit,
	}, nil
}

// Register ensures the ACME account for the client's key exists. It is
// idempotent: an account that already exists is treated as success.
func (c *Client) Register(ctx context.Context) error {
	acct := &xacme.Account{}
	if c.email != "" {
		acct.Contact = []string{"mailto:" + c.email}
	}
	if c.eabKID != "" && len(c.eabHMAC) > 0 {
		acct.ExternalAccountBinding = &xacme.ExternalAccountBinding{KID: c.eabKID, Key: c.eabHMAC}
	}
	_, err := c.ac.Register(ctx, acct, xacme.AcceptTOS)
	if err == nil || errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return nil
	}
	return errors.Join(ErrOrder, scrub(err))
}

// Obtain runs the DNS-01 order flow for domains against the certificate whose
// public key and subject are carried by csrDER (raw ASN.1 DER, not PEM):
// AuthorizeOrder, then for each pending authorization pick the dns-01 challenge,
// compute the TXT value, Present it, Accept the challenge and WaitAuthorization;
// then CreateOrderCert with the CSR, wait for issuance and PEM-encode the chain.
// Every published record is cleaned up (deferred) whether or not issuance
// succeeds. The whole call is bounded by Config.Timeout. Errors are one of the
// package sentinels joined with a scrubbed cause; the account key and DNS
// credentials never appear in them.
func (c *Client) Obtain(ctx context.Context, csrDER []byte, domains []string) (string, error) {
	if len(csrDER) == 0 || len(csrDER) > MaxCSRBytes {
		return "", ErrOrder
	}
	if len(domains) == 0 || len(domains) > MaxDomains {
		return "", ErrOrder
	}

	ctx, cancel := context.WithTimeout(ctx, c.limit)
	defer cancel()

	order, err := c.ac.AuthorizeOrder(ctx, xacme.DomainIDs(domains...))
	if err != nil {
		return "", wrap(ctx, ErrOrder, err)
	}

	// Track published records so every Present is matched by a CleanUp.
	type published struct{ domain, fqdn, value string }
	var records []published
	defer func() {
		for _, r := range records {
			// Best-effort cleanup on a fresh, bounded context so it still runs
			// when ctx is already done; failures are intentionally ignored.
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = c.dns.CleanUp(cctx, r.domain, r.fqdn, r.value)
			ccancel()
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := c.ac.GetAuthorization(ctx, authzURL)
		if err != nil {
			return "", wrap(ctx, ErrChallenge, err)
		}
		if authz.Status == xacme.StatusValid {
			continue // already satisfied (reused authorization)
		}
		chal := dns01Challenge(authz.Challenges)
		if chal == nil {
			return "", ErrChallenge
		}
		value, err := dns01Record(c.ac, chal.Token)
		if err != nil {
			return "", wrap(ctx, ErrChallenge, err)
		}
		domain := authz.Identifier.Value
		fqdn := "_acme-challenge." + domain
		if err := c.dns.Present(ctx, domain, fqdn, value); err != nil {
			return "", errors.Join(ErrProvider, scrub(err))
		}
		records = append(records, published{domain, fqdn, value})

		if _, err := c.ac.Accept(ctx, chal); err != nil {
			return "", wrap(ctx, ErrChallenge, err)
		}
		if _, err := c.ac.WaitAuthorization(ctx, authz.URI); err != nil {
			return "", wrap(ctx, ErrChallenge, err)
		}
	}

	// All authorizations are valid; wait for the order to be ready, then finalize.
	// Preserve the finalize URL from the original order: a bare ready-poll
	// response need not repeat it.
	finalizeURL := order.FinalizeURL
	if _, err = c.ac.WaitOrder(ctx, order.URI); err != nil {
		return "", wrap(ctx, ErrOrder, err)
	}
	ders, _, err := createOrderCert(c.ac, ctx, finalizeURL, csrDER, true)
	if err != nil {
		// Some CAs finalize asynchronously (e.g. Pebble): the finalize POST is
		// accepted but the order comes back "processing" with no inline
		// certificate URL, which CreateOrderCert cannot fetch. The finalize has
		// already been submitted, so wait for the order to reach "valid" and
		// fetch the certificate by its URL. If no URL ever appears the original
		// finalize error stands.
		o, werr := c.ac.WaitOrder(ctx, order.URI)
		if werr != nil {
			return "", wrap(ctx, ErrOrder, werr)
		}
		if o.CertURL == "" {
			return "", wrap(ctx, ErrOrder, err)
		}
		fetched, ferr := c.ac.FetchCert(ctx, o.CertURL, true)
		if ferr != nil {
			return "", wrap(ctx, ErrOrder, ferr)
		}
		ders = fetched
	}
	chain := encodeChainPEM(ders)
	if len(chain) == 0 {
		return "", ErrOrder
	}
	return string(chain), nil
}

// dns01Challenge returns the dns-01 challenge from a set, or nil if absent.
func dns01Challenge(chals []*xacme.Challenge) *xacme.Challenge {
	for _, ch := range chals {
		if ch != nil && ch.Type == "dns-01" {
			return ch
		}
	}
	return nil
}

// wrap maps a cause to the right sentinel: a deadline/cancellation becomes
// ErrTimeout, anything else joins sentinel with the scrubbed cause.
func wrap(ctx context.Context, sentinel, cause error) error {
	if ctx.Err() != nil || errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		return ErrTimeout
	}
	return errors.Join(sentinel, scrub(cause))
}

// scrub reduces a cause to a short, credential-free error. ACME/DNS transport
// errors can echo request bodies; we keep only the type-level message and drop
// any dynamic detail that could carry the account key or a DNS credential.
func scrub(err error) error {
	if err == nil {
		return nil
	}
	var ae *xacme.Error
	if errors.As(err, &ae) {
		// ACME problem documents carry a stable type/detail from the CA; keep
		// only the problem type, never headers or the JWS payload.
		return errors.New("acme: server rejected request (" + ae.ProblemType + ")")
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return errors.New("acme: network error contacting directory")
	}
	return errors.New("acme: request failed")
}

// encodeChainPEM concatenates DER certificates as PEM CERTIFICATE blocks.
func encodeChainPEM(ders [][]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

// GenerateAccountKey returns a fresh ECDSA P-256 key for a new ACME account.
func GenerateAccountKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// isLoopbackDirectory reports whether the directory URL's host is a loopback
// address or "localhost", the only place AllowInsecure is permitted.
func isLoopbackDirectory(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	host := hostOf(rawURL)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostOf extracts the host (without port) from an ACME directory URL, tolerating
// a missing scheme.
func hostOf(rawURL string) string {
	s := rawURL
	if i := indexOf(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := indexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
