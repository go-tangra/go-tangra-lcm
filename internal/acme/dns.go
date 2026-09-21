// Package acme drives DNS-01 certificate issuance against an ACME/Let's-Encrypt
// directory through a pluggable DNS-provider abstraction: the order flow, the
// challenge accounting and the TXT-record publishing are separated so the CA
// never has to embed a specific DNS vendor's SDK, credentials are passed in by
// the caller and never persisted or logged, and provider errors are surfaced
// without echoing the account key or the AUTH exchange (SR-ACME). This file
// holds the provider interface, the no-op/manual provider used with Pebble's
// PEBBLE_VA_ALWAYS_VALID and in tests, and the registry the API lists.
package acme

import (
	"context"
	"sync"
)

// MaxCredValueBytes bounds a single credential value handed to NewProvider, so
// an over-large secret is rejected as data rather than copied around.
const MaxCredValueBytes = 8 << 10

// DNSProvider publishes and removes the TXT record that answers a DNS-01
// challenge. domain is the certificate identifier (e.g. "example.com"), fqdn is
// the record name the CA queries ("_acme-challenge.example.com"), and value is
// the base64url TXT value computed from the challenge token. Implementations
// must be safe for a bounded, sequential order flow and must never log or
// return credential values in their errors.
type DNSProvider interface {
	Present(ctx context.Context, domain, fqdn, value string) error
	CleanUp(ctx context.Context, domain, fqdn, value string) error
}

// Interaction records one Present/CleanUp call for assertions in tests.
type Interaction struct {
	Op     string // "present" | "cleanup"
	Domain string
	FQDN   string
	Value  string
}

// NoopProvider satisfies DNSProvider without touching any DNS zone. It is used
// with Pebble's PEBBLE_VA_ALWAYS_VALID (where the VA never queries DNS) and in
// unit tests. It records every call so a test can assert Present/CleanUp ran,
// and it is safe for concurrent use. ManualProvider is an alias: the generic
// "manual" provider is exactly this no-op recorder, leaving the operator (or
// the always-valid VA) to satisfy the challenge out of band.
type NoopProvider struct {
	mu    sync.Mutex
	calls []Interaction
}

// ManualProvider is the generic operator-driven provider: a no-op recorder that
// assumes the TXT record is placed out of band (or that the VA is always-valid).
type ManualProvider = NoopProvider

// Present records the challenge and returns nil.
func (p *NoopProvider) Present(_ context.Context, domain, fqdn, value string) error {
	p.record("present", domain, fqdn, value)
	return nil
}

// CleanUp records the removal and returns nil.
func (p *NoopProvider) CleanUp(_ context.Context, domain, fqdn, value string) error {
	p.record("cleanup", domain, fqdn, value)
	return nil
}

func (p *NoopProvider) record(op, domain, fqdn, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, Interaction{Op: op, Domain: domain, FQDN: fqdn, Value: value})
}

// Calls returns a copy of the recorded interactions, in order.
func (p *NoopProvider) Calls() []Interaction {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Interaction, len(p.calls))
	copy(out, p.calls)
	return out
}

// ProviderField describes one credential/config input a provider needs. Secret
// fields hold private material (API tokens, secret keys) and must be stored
// sealed and redacted on read; Required fields must be present to construct the
// provider.
type ProviderField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
}

// ProviderInfo is one entry in the registry the API's GET /dns-providers lists.
type ProviderInfo struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"display_name"`
	Fields      []ProviderField `json:"fields"`
}

// registry is the static list of DNS providers the module advertises. Only the
// generic "manual" provider has a working in-process adapter today (NewProvider
// returns the no-op recorder for it); the rest are advertised so the API and UI
// can collect credentials, and real adapters can be added later without
// changing this registry's shape. Field keys are stable identifiers used as the
// sealed-settings JSON keys; secret fields are marked so the caller seals and
// redacts them.
var registry = []ProviderInfo{
	{
		Name:        "cloudflare",
		DisplayName: "Cloudflare",
		Fields: []ProviderField{
			{Key: "api_token", Label: "API Token", Secret: true, Required: true},
			{Key: "zone_id", Label: "Zone ID (optional)", Secret: false, Required: false},
		},
	},
	{
		Name:        "route53",
		DisplayName: "Amazon Route 53",
		Fields: []ProviderField{
			{Key: "access_key_id", Label: "Access Key ID", Secret: false, Required: true},
			{Key: "secret_access_key", Label: "Secret Access Key", Secret: true, Required: true},
			{Key: "region", Label: "Region (optional)", Secret: false, Required: false},
			{Key: "hosted_zone_id", Label: "Hosted Zone ID (optional)", Secret: false, Required: false},
		},
	},
	{
		Name:        "gcloud",
		DisplayName: "Google Cloud DNS",
		Fields: []ProviderField{
			{Key: "project", Label: "Project ID", Secret: false, Required: true},
			{Key: "service_account_key", Label: "Service Account Key (JSON)", Secret: true, Required: true},
		},
	},
	{
		Name:        "digitalocean",
		DisplayName: "DigitalOcean",
		Fields: []ProviderField{
			{Key: "auth_token", Label: "API Token", Secret: true, Required: true},
		},
	},
	{
		Name:        "acmedns",
		DisplayName: "ACME-DNS",
		Fields: []ProviderField{
			{Key: "server_url", Label: "Server URL", Secret: false, Required: true},
			{Key: "username", Label: "Username", Secret: false, Required: true},
			{Key: "password", Label: "Password", Secret: true, Required: true},
			{Key: "subdomain", Label: "Subdomain", Secret: false, Required: true},
		},
	},
	{
		Name:        "powerdns",
		DisplayName: "PowerDNS",
		Fields: []ProviderField{
			{Key: "api_url", Label: "API URL", Secret: false, Required: true},
			{Key: "api_key", Label: "API Key", Secret: true, Required: true},
			{Key: "server_name", Label: "Server Name (optional)", Secret: false, Required: false},
		},
	},
	{
		Name:        "hurricane",
		DisplayName: "Hurricane Electric",
		Fields: []ProviderField{
			{Key: "api_token", Label: "API Token", Secret: true, Required: true},
		},
	},
	{
		Name:        "httpreq",
		DisplayName: "HTTP Request",
		Fields: []ProviderField{
			{Key: "endpoint", Label: "Endpoint URL", Secret: false, Required: true},
			{Key: "username", Label: "Username (optional)", Secret: false, Required: false},
			{Key: "password", Label: "Password (optional)", Secret: true, Required: false},
		},
	},
	{
		Name:        "easydns",
		DisplayName: "easyDNS",
		Fields: []ProviderField{
			{Key: "token", Label: "API Token", Secret: false, Required: true},
			{Key: "key", Label: "API Key", Secret: true, Required: true},
		},
	},
	{
		Name:        "manual",
		DisplayName: "Manual / Out-of-band",
		Fields:      []ProviderField{},
	},
}

// Providers returns a copy of the DNS-provider registry the API lists. The
// slice and its field slices are copied so callers cannot mutate the registry.
func Providers() []ProviderInfo {
	out := make([]ProviderInfo, len(registry))
	for i, p := range registry {
		fields := make([]ProviderField, len(p.Fields))
		copy(fields, p.Fields)
		out[i] = ProviderInfo{Name: p.Name, DisplayName: p.DisplayName, Fields: fields}
	}
	return out
}

// lookup returns the registry entry for name, or false if unknown.
func lookup(name string) (ProviderInfo, bool) {
	for _, p := range registry {
		if p.Name == name {
			return p, true
		}
	}
	return ProviderInfo{}, false
}

// NewProvider constructs a DNSProvider for a registry name from the supplied
// credentials. It returns the no-op/manual recorder for "manual" (the only
// adapter with a working in-process implementation today), and
// ErrUnsupportedProvider for every registered-but-not-yet-implemented provider
// and for unknown names. It never panics and never includes a credential value
// in its error: the returned error names only the provider, never the secret.
func NewProvider(name string, creds map[string]string) (DNSProvider, error) {
	for _, v := range creds {
		if len(v) > MaxCredValueBytes {
			// Reject over-large input as data; the value itself is never echoed.
			return nil, ErrProvider
		}
	}
	switch name {
	case "manual":
		return &NoopProvider{}, nil
	default:
		if _, ok := lookup(name); ok {
			// Registered for listing, but no adapter is wired yet.
			return nil, ErrUnsupportedProvider
		}
		return nil, ErrUnsupportedProvider
	}
}
