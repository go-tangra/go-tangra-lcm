package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func valid() Config {
	c := Default()
	c.ServiceName, c.TrustDomain, c.Env = "lcm", "example.org", "dev"
	c.Identity.Provider = "file"
	c.Identity.File.Cert, c.Identity.File.Key, c.Identity.File.Bundle = "c", "k", "b"
	c.Authz.Source, c.Authz.Path = "file", "p.yaml"
	c.Config.Limits.MaxRequestBytes = 17 << 20
	c.DB.DSN = "postgres://lcm_app:x@db/lcm?sslmode=disable"
	c.Valkey.Addresses = []string{"127.0.0.1:6379"}
	c.Valkey.AllowPlaintext = true
	c.KEK.Path = "deploy/kek.dev"
	c.ACME.AllowPlaintextDNS = true
	c.Gateway.Issuer = "https://localhost:8443"
	return c
}

func production(c *Config) {
	c.Env = "production"
	c.DB.DSN = "postgres://u:p@db/lcm?sslmode=verify-full"
	c.Valkey.AllowPlaintext = false
	c.ACME.AllowPlaintextDNS = false
}

func TestDefaultsAreSecure(t *testing.T) {
	c := Default()
	if c.Valkey.AllowPlaintext || c.ACME.AllowPlaintextDNS {
		t.Fatal("plaintext must be opt-in")
	}
	if c.KEK.Source != "file" || c.Renewal.IntervalSeconds != 15 || c.Renewal.LeaseSeconds != 60 || c.Renewal.Workers != 4 ||
		c.Gateway.Service != "gateway" || c.Limits.BackupMaxBytes != 16<<20 || c.Limits.CSRMaxBytes != 16<<10 ||
		c.Limits.StreamsPerUser != 5 || c.Limits.StreamsPerTenant != 2000 || c.Limits.ReplayWindowSeconds != 300 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestValidateAcceptsDevAndProduction(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.ReplayWindow() != 5*time.Minute || c.RenewalInterval() != 15*time.Second || c.LeaseDuration() != time.Minute || c.LongLivedWindow() != 30*24*time.Hour {
		t.Fatal("durations")
	}
	if w := c.Warnings(); len(w) < 2 || !strings.Contains(strings.Join(w, "\n"), "acme.allow_plaintext_dns") || !strings.Contains(strings.Join(w, "\n"), "valkey.allow_plaintext") {
		t.Fatalf("warnings %v", w)
	}
	production(&c)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.DB.DSN = "postgres://u:p@db/lcm?sslmode=verify-ca"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.KEK = KEK{Source: "env", Env: "LCM_KEK"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"service_name":        func(c *Config) { c.ServiceName = "" },
		"db.dsn required":     func(c *Config) { c.DB.DSN = "" },
		"db.dsn prod ssl":     func(c *Config) { production(c); c.DB.DSN = "postgres://u:p@db/lcm?sslmode=disable" },
		"valkey addresses":    func(c *Config) { c.Valkey.Addresses = nil },
		"valkey plaintext":    func(c *Config) { production(c); c.Valkey.AllowPlaintext = true },
		"kek file path":       func(c *Config) { c.KEK = KEK{Source: "file"} },
		"kek env":             func(c *Config) { c.KEK = KEK{Source: "env"} },
		"kek source":          func(c *Config) { c.KEK = KEK{Source: "vault"} },
		"renewal interval":    func(c *Config) { c.Renewal.IntervalSeconds = 0 },
		"renewal lease":       func(c *Config) { c.Renewal.LeaseSeconds = 1 },
		"renewal workers":     func(c *Config) { c.Renewal.Workers = 0 },
		"renewal fraction":    func(c *Config) { c.Renewal.ShortLivedFraction = 0 },
		"renewal long lived":  func(c *Config) { c.Renewal.LongLivedDays = 0 },
		"acme plaintext prod": func(c *Config) { production(c); c.ACME.AllowPlaintextDNS = true },
		"gateway service":     func(c *Config) { c.Gateway.Service = "" },
		"gateway issuer":      func(c *Config) { c.Gateway.Issuer = "http://insecure" },
		"backup max bytes":    func(c *Config) { c.Limits.BackupMaxBytes = 1 << 20 },
		"max request too low": func(c *Config) { c.Config.Limits.MaxRequestBytes = 1 << 10 },
		"csr max bytes":       func(c *Config) { c.Limits.CSRMaxBytes = 1 },
		"webhook max bytes":   func(c *Config) { c.Limits.WebhookMaxBytes = 1 },
		"streams per user":    func(c *Config) { c.Limits.StreamsPerUser = 0 },
		"replay window":       func(c *Config) { c.Limits.ReplayWindowSeconds = 1 },
		"dns service":         func(c *Config) { c.DNS.Service = "dns:9965/evil" },
	}
	for name, mut := range cases {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("db:\n  max_conns: 32\nrenewal:\n  workers: 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DB.MaxConns != 32 || c.Renewal.Workers != 8 {
		t.Fatalf("loaded %+v", c)
	}
	// Missing file.
	if _, err := Load(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Fatal("missing file: expected error")
	}
	// Unknown field is rejected.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("not_a_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Fatal("unknown field: expected error")
	}
}

func TestDNSServiceOptional(t *testing.T) {
	c := valid()
	if c.DNS.Service != "" || c.Validate() != nil {
		t.Fatalf("default dns section = %+v", c.DNS)
	}
	c.DNS.Service = "dns"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
