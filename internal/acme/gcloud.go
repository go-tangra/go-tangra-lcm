package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// GoogleDNSAPI is the Cloud DNS v1 API base URL.
const GoogleDNSAPI = "https://dns.googleapis.com/dns/v1"

// GoogleTokenURL is Google's OAuth 2.0 token endpoint. The service account
// key's own token_uri is ignored: a stored key never redirects lcm elsewhere.
const GoogleTokenURL = "https://oauth2.googleapis.com/token"

// googleDNSScope is the narrowest OAuth scope that may change record sets.
const googleDNSScope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"

// maxGoogleBody bounds a Google API response read into memory.
const maxGoogleBody = 1 << 20

// gcloudAttempts bounds the read-modify-write retries when another change to
// the same record set wins the race (HTTP 409/412).
const gcloudAttempts = 4

// GCloudOptions overrides the endpoints, HTTP client, propagation wait, clock
// and change polling (tests).
type GCloudOptions struct {
	BaseURL     string
	TokenURL    string
	HTTP        *http.Client
	Propagation Propagation
	Now         func() time.Time
	PollEvery   time.Duration
}

// GCloud answers DNS-01 challenges by changing TXT record sets through the
// Cloud DNS v1 API, authenticated as a service account (role DNS
// Administrator, or dns.changes.create/get, dns.resourceRecordSets.list and
// dns.managedZones.get/list). Cloud DNS keeps all TXT values of a name in one
// record set, so a value is added to or removed from that set and values of
// other orders (a wildcard and its base name) are kept. The key and the access
// token are never logged nor returned in errors; Google's messages are.
type GCloud struct {
	project, zoneName string
	email, keyID      string
	key               *rsa.PrivateKey
	base, tokenURL    string
	hc                *http.Client
	wait              Propagation
	now               func() time.Time
	pollEvery         time.Duration

	mu     sync.Mutex
	token  string
	expiry time.Time
}

type gcZone struct {
	Name        string   `json:"name"`
	DNSName     string   `json:"dnsName"`
	NameServers []string `json:"nameServers"`
	Visibility  string   `json:"visibility"`
}

type gcRRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

// errGCloudConflict is a lost read-modify-write race; the change is retried.
var errGCloudConflict = errors.New("gcloud: concurrent change")

// NewGCloud builds the provider from its credentials: service_account_key
// (the JSON key file, or that file base64-encoded) is required; project
// defaults to the key's project_id; managed_zone (the zone's name, not its
// DNS name) skips the zone lookup.
func NewGCloud(creds map[string]string, opts GCloudOptions) (*GCloud, error) {
	raw := strings.TrimSpace(creds["service_account_key"])
	if raw == "" {
		return nil, fmt.Errorf("%w: gcloud: service_account_key is required", ErrProvider)
	}
	if !strings.HasPrefix(raw, "{") {
		if dec, err := base64.StdEncoding.DecodeString(raw); err == nil {
			raw = strings.TrimSpace(string(dec))
		}
	}
	var sa struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
	}
	if err := json.Unmarshal([]byte(raw), &sa); err != nil {
		return nil, fmt.Errorf("%w: gcloud: service_account_key is not a JSON key file", ErrProvider)
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("%w: gcloud: service_account_key must be a service account key (type service_account, with client_email and private_key)", ErrProvider)
	}
	key, err := parseRSAKey(sa.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: gcloud: service_account_key: private_key is not an RSA private key", ErrProvider)
	}
	project := strings.TrimSpace(creds["project"])
	if project == "" {
		project = sa.ProjectID
	}
	if project == "" {
		return nil, fmt.Errorf("%w: gcloud: project is required (the key names none)", ErrProvider)
	}
	g := &GCloud{project: project, zoneName: strings.TrimSpace(creds["managed_zone"]), email: sa.ClientEmail, keyID: sa.PrivateKeyID, key: key,
		base: GoogleDNSAPI, tokenURL: GoogleTokenURL, hc: &http.Client{Timeout: 30 * time.Second}, wait: waitPropagation, now: time.Now, pollEvery: 2 * time.Second}
	if opts.BaseURL != "" {
		g.base = strings.TrimRight(opts.BaseURL, "/")
	}
	if opts.TokenURL != "" {
		g.tokenURL = opts.TokenURL
	}
	if opts.HTTP != nil {
		g.hc = opts.HTTP
	}
	if opts.Propagation != nil {
		g.wait = opts.Propagation
	}
	if opts.Now != nil {
		g.now = opts.Now
	}
	if opts.PollEvery > 0 {
		g.pollEvery = opts.PollEvery
	}
	return g, nil
}

func parseRSAKey(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Present adds value to the TXT record set of fqdn, then waits until it is visible.
func (g *GCloud) Present(ctx context.Context, domain, fqdn, value string) error {
	zone, err := g.zone(ctx, domain)
	if err != nil {
		return err
	}
	if err := g.update(ctx, zone.Name, fqdn, func(vals []string) []string {
		if slices.Contains(vals, txtData(value)) {
			return nil
		}
		return append(slices.Clone(vals), txtData(value))
	}); err != nil {
		return err
	}
	g.wait(ctx, fqdn, value, zone.NameServers)
	return nil
}

// CleanUp removes value from the TXT record set of fqdn, keeping other values.
func (g *GCloud) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	zone, err := g.zone(ctx, domain)
	if err != nil {
		return err
	}
	return g.update(ctx, zone.Name, fqdn, func(vals []string) []string {
		if !slices.Contains(vals, txtData(value)) {
			return nil
		}
		return slices.DeleteFunc(slices.Clone(vals), func(v string) bool { return v == txtData(value) })
	})
}

// update replaces the TXT record set of fqdn with edit(current values) in one
// change, retrying when another change to it lands first. edit returns nil
// when nothing needs to change; an empty non-nil slice deletes the set.
func (g *GCloud) update(ctx context.Context, zone, fqdn string, edit func([]string) []string) error {
	name := dnsName(fqdn)
	for attempt := 1; ; attempt++ {
		cur, err := g.rrset(ctx, zone, name)
		if err != nil {
			return err
		}
		var vals []string
		if cur != nil {
			vals = cur.RRDatas
		}
		next := edit(vals)
		if next == nil {
			return nil
		}
		change := map[string][]gcRRSet{}
		if cur != nil {
			change["deletions"] = []gcRRSet{*cur}
		}
		if len(next) > 0 {
			ttl := 60
			if cur != nil && cur.TTL > 0 {
				ttl = cur.TTL
			}
			change["additions"] = []gcRRSet{{Name: name, Type: "TXT", TTL: ttl, RRDatas: next}}
		}
		err = g.apply(ctx, zone, change)
		if !errors.Is(err, errGCloudConflict) {
			return err
		}
		if attempt == gcloudAttempts {
			return fmt.Errorf("%w: gcloud: the TXT record set of %s kept changing; giving up after %d attempts", ErrProvider, name, attempt)
		}
	}
}

// apply submits one change and waits (bounded) until Cloud DNS reports it done.
func (g *GCloud) apply(ctx context.Context, zone string, change map[string][]gcRRSet) error {
	var ch struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	path := g.zonePath(zone) + "/changes"
	if err := g.call(ctx, http.MethodPost, path, change, &ch); err != nil {
		return err
	}
	deadline := g.now().Add(time.Minute)
	for ch.Status != "done" && ch.ID != "" && g.now().Before(deadline) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: gcloud: %v", ErrProvider, ctx.Err())
		case <-time.After(g.pollEvery):
		}
		if err := g.call(ctx, http.MethodGet, path+"/"+url.PathEscape(ch.ID), nil, &ch); err != nil {
			return err
		}
	}
	return nil // a change still pending is applied by Cloud DNS; propagation is waited for next
}

func (g *GCloud) rrset(ctx context.Context, zone, name string) (*gcRRSet, error) {
	var out struct {
		RRSets []gcRRSet `json:"rrsets"`
	}
	q := url.Values{"name": {name}, "type": {"TXT"}}
	if err := g.call(ctx, http.MethodGet, g.zonePath(zone)+"/rrsets?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	for i := range out.RRSets {
		if strings.EqualFold(out.RRSets[i].Name, name) && out.RRSets[i].Type == "TXT" {
			return &out.RRSets[i], nil
		}
	}
	return nil, nil
}

// zone resolves the configured managed zone or finds the closest enclosing
// public zone of domain in the project.
func (g *GCloud) zone(ctx context.Context, domain string) (gcZone, error) {
	if g.zoneName != "" {
		var z gcZone
		if err := g.call(ctx, http.MethodGet, g.zonePath(g.zoneName), nil, &z); err != nil {
			return gcZone{}, err
		}
		return z, nil
	}
	for _, name := range zoneCandidates(domain) {
		var out struct {
			ManagedZones []gcZone `json:"managedZones"`
		}
		q := url.Values{"dnsName": {dnsName(name)}}
		if err := g.call(ctx, http.MethodGet, "/projects/"+url.PathEscape(g.project)+"/managedZones?"+q.Encode(), nil, &out); err != nil {
			return gcZone{}, err
		}
		for _, z := range out.ManagedZones {
			if z.Visibility != "private" { // the CA resolves public DNS only
				return z, nil
			}
		}
	}
	return gcZone{}, fmt.Errorf("%w: gcloud: no public Cloud DNS zone for %s in project %s (set managed_zone, or allow dns.managedZones.list)", ErrProvider, domain, g.project)
}

func (g *GCloud) zonePath(zone string) string {
	return "/projects/" + url.PathEscape(g.project) + "/managedZones/" + url.PathEscape(zone)
}

// call performs one Cloud DNS request with a service account access token.
func (g *GCloud) call(ctx context.Context, method, path string, in, out any) error {
	token, err := g.accessToken(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("%w: gcloud: encode request", ErrProvider)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, rd)
	if err != nil {
		return fmt.Errorf("%w: gcloud: build request", ErrProvider)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	op := method + " " + strings.SplitN(path, "?", 2)[0]
	raw, status, err := g.do(req)
	if err != nil {
		return fmt.Errorf("%w: gcloud: %s %v", ErrProvider, op, err)
	}
	if status >= 300 {
		if status == http.StatusConflict || status == http.StatusPreconditionFailed {
			return errGCloudConflict
		}
		var env struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &env)
		msg := env.Error.Message
		if msg == "" {
			msg = "request refused"
		}
		if env.Error.Status != "" {
			msg += " (" + env.Error.Status + ")"
		}
		return fmt.Errorf("%w: gcloud: %s: HTTP %d: %s", ErrProvider, op, status, strings.ReplaceAll(msg, token, "[redacted]"))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%w: gcloud: %s: unexpected response", ErrProvider, op)
		}
	}
	return nil
}

// accessToken returns a cached access token or exchanges a freshly signed
// JWT assertion for one (RFC 7523, Google's service account flow).
func (g *GCloud) accessToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.token != "" && now.Before(g.expiry) {
		return g.token, nil
	}
	assertion, err := g.assertion(now)
	if err != nil {
		return "", fmt.Errorf("%w: gcloud: sign token request", ErrProvider)
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: gcloud: build token request", ErrProvider)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	raw, status, err := g.do(req)
	if err != nil {
		return "", fmt.Errorf("%w: gcloud: token %v", ErrProvider, err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &tok)
	if status >= 300 || tok.AccessToken == "" {
		msg := "no access token"
		if tok.Error != "" {
			msg = strings.TrimSuffix(tok.Error+": "+tok.Description, ": ")
		}
		return "", fmt.Errorf("%w: gcloud: service account %s refused: HTTP %d: %s", ErrProvider, g.email, status, msg)
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 2*time.Minute {
		ttl = 2 * time.Minute
	}
	g.token, g.expiry = tok.AccessToken, now.Add(ttl-time.Minute)
	return g.token, nil
}

// assertion is the RS256-signed JWT that asks for a Cloud DNS access token.
func (g *GCloud) assertion(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if g.keyID != "" {
		header["kid"] = g.keyID
	}
	claims := map[string]any{"iss": g.email, "scope": googleDNSScope, "aud": g.tokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// do sends req and reads a bounded response body.
func (g *GCloud) do(req *http.Request) ([]byte, int, error) {
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, 0, errors.New("unreachable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGoogleBody+1))
	if err != nil || len(raw) > maxGoogleBody {
		return nil, resp.StatusCode, errors.New("unreadable response")
	}
	return raw, resp.StatusCode, nil
}

// dnsName is name as Cloud DNS spells it: lower case, fully qualified.
func dnsName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}

// txtData is value as a quoted TXT character string (Cloud DNS rrdata form).
func txtData(value string) string { return `"` + value + `"` }
