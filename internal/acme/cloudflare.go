package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudflareAPI is the Cloudflare v4 API base URL.
const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// maxCloudflareBody bounds a Cloudflare API response read into memory.
const maxCloudflareBody = 1 << 20

// Propagation waits (bounded) until the TXT value is visible; servers are the
// zone's authoritative name servers when known. It never fails: the CA's own
// validation is the final word.
type Propagation func(ctx context.Context, fqdn, value string, servers []string)

// CloudflareOptions overrides the API endpoint, HTTP client and propagation
// wait (tests).
type CloudflareOptions struct {
	BaseURL     string
	HTTP        *http.Client
	Propagation Propagation
}

// Cloudflare answers DNS-01 challenges by creating and deleting TXT records
// through the Cloudflare v4 API with a scoped API token (Zone.DNS:Edit; plus
// Zone:Read when no zone_id is configured). The token is never logged nor
// returned in errors; Cloudflare's own error messages are.
type Cloudflare struct {
	token  string
	zoneID string
	base   string
	hc     *http.Client
	wait   Propagation

	mu      sync.Mutex
	records map[string]cfRecord // fqdn + "\x00" + value
}

type cfRecord struct{ zone, id string }

type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

// NewCloudflare builds the provider from its credentials (api_token required,
// zone_id optional).
func NewCloudflare(creds map[string]string, opts CloudflareOptions) (*Cloudflare, error) {
	token := strings.TrimSpace(creds["api_token"])
	if token == "" {
		return nil, fmt.Errorf("%w: cloudflare: api_token is required", ErrProvider)
	}
	c := &Cloudflare{token: token, zoneID: strings.TrimSpace(creds["zone_id"]), base: CloudflareAPI,
		hc: &http.Client{Timeout: 30 * time.Second}, wait: waitPropagation, records: map[string]cfRecord{}}
	if opts.BaseURL != "" {
		c.base = strings.TrimRight(opts.BaseURL, "/")
	}
	if opts.HTTP != nil {
		c.hc = opts.HTTP
	}
	if opts.Propagation != nil {
		c.wait = opts.Propagation
	}
	return c, nil
}

// Present creates the TXT record, then waits until it is visible.
func (c *Cloudflare) Present(ctx context.Context, domain, fqdn, value string) error {
	zone, err := c.zone(ctx, domain)
	if err != nil {
		return err
	}
	var created struct {
		ID string `json:"id"`
	}
	body := map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 60}
	if err := c.call(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone.ID)+"/dns_records", body, &created); err != nil {
		return err
	}
	c.mu.Lock()
	c.records[fqdn+"\x00"+value] = cfRecord{zone: zone.ID, id: created.ID}
	c.mu.Unlock()
	c.wait(ctx, fqdn, value, zone.NameServers)
	return nil
}

// CleanUp deletes the TXT record created by Present (looked up by name and
// content when this instance did not create it).
func (c *Cloudflare) CleanUp(ctx context.Context, domain, fqdn, value string) error {
	key := fqdn + "\x00" + value
	c.mu.Lock()
	rec, ok := c.records[key]
	c.mu.Unlock()
	var ids []string
	zoneID := rec.zone
	if ok {
		ids = []string{rec.id}
	} else {
		zone, err := c.zone(ctx, domain)
		if err != nil {
			return err
		}
		zoneID = zone.ID
		var found []struct {
			ID string `json:"id"`
		}
		q := url.Values{"type": {"TXT"}, "name": {fqdn}, "content": {value}}
		if err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), nil, &found); err != nil {
			return err
		}
		for _, f := range found {
			ids = append(ids, f.ID)
		}
	}
	for _, id := range ids {
		if err := c.call(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
	}
	c.mu.Lock()
	delete(c.records, key)
	c.mu.Unlock()
	return nil
}

// zone resolves the configured zone (name servers when the token may read it)
// or finds the closest enclosing zone of domain.
func (c *Cloudflare) zone(ctx context.Context, domain string) (cfZone, error) {
	if c.zoneID != "" {
		var z cfZone
		if err := c.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.zoneID), nil, &z); err != nil {
			// DNS-edit-only tokens cannot read the zone; the id alone suffices.
			return cfZone{ID: c.zoneID}, nil
		}
		z.ID = c.zoneID
		return z, nil
	}
	for _, name := range zoneCandidates(domain) {
		var zones []cfZone
		q := url.Values{"name": {name}}
		if err := c.call(ctx, http.MethodGet, "/zones?"+q.Encode(), nil, &zones); err != nil {
			return cfZone{}, err
		}
		if len(zones) > 0 {
			return zones[0], nil
		}
	}
	return cfZone{}, fmt.Errorf("%w: cloudflare: no Cloudflare zone for %s visible to the token (set zone_id, or allow Zone:Read)", ErrProvider, domain)
}

// call performs one API request; out receives the envelope's result.
func (c *Cloudflare) call(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("%w: cloudflare: encode request", ErrProvider)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return fmt.Errorf("%w: cloudflare: build request", ErrProvider)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: cloudflare: %s %s unreachable", ErrProvider, method, strings.SplitN(path, "?", 2)[0])
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudflareBody+1))
	if err != nil || len(raw) > maxCloudflareBody {
		return fmt.Errorf("%w: cloudflare: unreadable response", ErrProvider)
	}
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%w: cloudflare: HTTP %d, unexpected response", ErrProvider, resp.StatusCode)
	}
	if !env.Success || resp.StatusCode >= 300 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%s (%d)", e.Message, e.Code))
		}
		if len(msgs) == 0 {
			msgs = append(msgs, "request refused")
		}
		return fmt.Errorf("%w: cloudflare: HTTP %d: %s", ErrProvider, resp.StatusCode, strings.ReplaceAll(strings.Join(msgs, "; "), c.token, "[redacted]"))
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("%w: cloudflare: unexpected result", ErrProvider)
		}
	}
	return nil
}

// zoneCandidates lists domain and its parents, longest first, excluding the TLD.
func zoneCandidates(domain string) []string {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(domain), "."), ".")
	var out []string
	for i := 0; i < len(labels)-1; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// waitPropagation polls the zone's authoritative name servers (or public
// resolvers when unknown) until the TXT value is visible, for at most two
// minutes.
func waitPropagation(ctx context.Context, fqdn, value string, servers []string) {
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "8.8.8.8"}
	}
	lookup := func(ctx context.Context, name string) ([]string, error) {
		var last error
		for _, s := range servers {
			addr := net.JoinHostPort(s, "53")
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}}
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			txt, err := r.LookupTXT(lctx, name)
			cancel()
			if err == nil {
				return txt, nil
			}
			last = err
		}
		return nil, last
	}
	waitTXT(ctx, lookup, fqdn, value, 3*time.Second, 2*time.Minute)
}

// waitTXT polls lookup until value appears, the deadline passes or ctx ends.
func waitTXT(ctx context.Context, lookup func(context.Context, string) ([]string, error), fqdn, value string, every, max time.Duration) bool {
	deadline := time.Now().Add(max)
	for {
		if ctx.Err() != nil {
			return false
		}
		if txt, err := lookup(ctx, fqdn); err == nil {
			for _, t := range txt {
				if t == value {
					return true
				}
			}
		}
		if time.Now().Add(every).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(every):
		}
	}
}
