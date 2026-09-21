// Package config loads and validates the lcm service configuration: the Freya
// framework config plus the module's own sections. Every value is explicit;
// insecure opt-outs are named and logged at start.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	fconfig "github.com/go-freya/freya/config"
	"gopkg.in/yaml.v3"
)

// Config is the lcm service configuration.
type Config struct {
	fconfig.Config `yaml:",inline"`

	DB      DB      `yaml:"db"`
	Valkey  Valkey  `yaml:"valkey"`
	KEK     KEK     `yaml:"kek"`
	Renewal Renewal `yaml:"renewal"`
	Gateway Gateway `yaml:"gateway"`
	ACME    ACME    `yaml:"acme"`
	Limits  Limits  `yaml:"limits_lcm"`
	// EnrollListener, if set, runs a server-auth-only (no client cert) TLS
	// listener serving only POST /api/lcm/v1/enroll, so a service with no SVID
	// yet (e.g. the gateway) can enroll directly with a join token.
	EnrollListener string `yaml:"enroll_listener"`
}

// DB configures TimescaleDB.
type DB struct {
	DSN        string `yaml:"dsn"`         // application role (no BYPASSRLS)
	MigrateDSN string `yaml:"migrate_dsn"` // migration role; empty = DSN
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey configures the live-event streams, the renewal lease and rate limits.
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"`
}

// KEK names where the 32-byte key-encryption key comes from (research R5).
type KEK struct {
	Source string `yaml:"source"` // file | env
	Path   string `yaml:"path"`
	Env    string `yaml:"env"`
}

// Renewal configures the distributed renewal scheduler (research R7).
type Renewal struct {
	IntervalSeconds    int     `yaml:"interval_seconds"`
	LeaseSeconds       int     `yaml:"lease_seconds"`
	Workers            int     `yaml:"workers"`
	ShortLivedFraction float64 `yaml:"short_lived_fraction"` // renew short SVIDs at this fraction of TTL remaining
	LongLivedDays      int     `yaml:"long_lived_days"`      // renew longer certs this many days before expiry
}

// Gateway names the application gateway and the platform token issuer.
type Gateway struct {
	Service string `yaml:"service"`
	Issuer  string `yaml:"issuer"`
}

// ACME bounds outbound ACME/DNS behaviour.
type ACME struct {
	AllowPlaintextDNS bool `yaml:"allow_plaintext_dns"` // development mock DNS/ACME only
}

// Limits bound the module's own request shapes and rates.
type Limits struct {
	BackupMaxBytes      int64 `yaml:"backup_max_bytes"`
	CSRMaxBytes         int64 `yaml:"csr_max_bytes"`
	WebhookMaxBytes     int64 `yaml:"webhook_max_bytes"`
	StreamsPerUser      int   `yaml:"streams_per_user"`
	StreamsPerTenant    int   `yaml:"streams_per_tenant"`
	ReplayWindowSeconds int   `yaml:"replay_window_seconds"`
}

// Default returns secure defaults on top of the Freya defaults.
func Default() Config {
	return Config{
		Config:  fconfig.Default(),
		DB:      DB{MaxConns: 16},
		KEK:     KEK{Source: "file"},
		Renewal: Renewal{IntervalSeconds: 15, LeaseSeconds: 60, Workers: 4, ShortLivedFraction: 0.5, LongLivedDays: 30},
		Gateway: Gateway{Service: "gateway"},
		Limits: Limits{BackupMaxBytes: 16 << 20, CSRMaxBytes: 16 << 10, WebhookMaxBytes: 64 << 10,
			StreamsPerUser: 5, StreamsPerTenant: 2000, ReplayWindowSeconds: 300},
	}
}

// Load reads YAML over Default(); unknown fields are rejected. Not yet validated.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the Freya config and every module section.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	prod := c.IsProduction()
	if c.DB.DSN == "" {
		return errors.New("config: db.dsn is required")
	}
	if prod && !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		return errors.New("config: db.dsn must use sslmode=verify-full (or verify-ca) in production")
	}
	if len(c.Valkey.Addresses) == 0 {
		return errors.New("config: valkey.addresses is required")
	}
	if prod && c.Valkey.AllowPlaintext {
		return errors.New("config: valkey.allow_plaintext is not permitted in production")
	}
	switch c.KEK.Source {
	case "file":
		if c.KEK.Path == "" {
			return errors.New("config: kek.path is required for kek.source file")
		}
	case "env":
		if c.KEK.Env == "" {
			return errors.New("config: kek.env is required for kek.source env")
		}
	default:
		return errors.New("config: kek.source must be file or env")
	}
	if c.Renewal.IntervalSeconds < 1 || c.Renewal.IntervalSeconds > 60 {
		return errors.New("config: renewal.interval_seconds must be within [1, 60]")
	}
	if c.Renewal.LeaseSeconds < c.Renewal.IntervalSeconds || c.Renewal.LeaseSeconds > 600 {
		return errors.New("config: renewal.lease_seconds must be within [interval, 600]")
	}
	if c.Renewal.Workers < 1 || c.Renewal.Workers > 64 {
		return errors.New("config: renewal.workers must be within [1, 64]")
	}
	if c.Renewal.ShortLivedFraction <= 0 || c.Renewal.ShortLivedFraction >= 1 {
		return errors.New("config: renewal.short_lived_fraction must be within (0, 1)")
	}
	if c.Renewal.LongLivedDays < 1 || c.Renewal.LongLivedDays > 365 {
		return errors.New("config: renewal.long_lived_days must be within [1, 365]")
	}
	if prod && c.ACME.AllowPlaintextDNS {
		return errors.New("config: acme.allow_plaintext_dns is not permitted in production")
	}
	if c.Gateway.Service == "" {
		return errors.New("config: gateway.service is required")
	}
	if iu, err := url.Parse(c.Gateway.Issuer); err != nil || iu.Scheme != "https" || iu.Host == "" {
		return errors.New("config: gateway.issuer must be an https origin")
	}
	if c.Limits.BackupMaxBytes < 4<<20 || c.Limits.BackupMaxBytes > 64<<20 {
		return errors.New("config: limits_lcm.backup_max_bytes must be within [4 MiB, 64 MiB]")
	}
	if c.Config.Limits.MaxRequestBytes < c.Limits.BackupMaxBytes {
		return errors.New("config: limits.max_request_bytes must be at least limits_lcm.backup_max_bytes (backup uploads)")
	}
	if c.Limits.CSRMaxBytes < 1<<10 || c.Limits.CSRMaxBytes > 64<<10 {
		return errors.New("config: limits_lcm.csr_max_bytes must be within [1 KiB, 64 KiB]")
	}
	if c.Limits.WebhookMaxBytes < 1<<10 || c.Limits.WebhookMaxBytes > 1<<20 {
		return errors.New("config: limits_lcm.webhook_max_bytes must be within [1 KiB, 1 MiB]")
	}
	if c.Limits.StreamsPerUser <= 0 || c.Limits.StreamsPerTenant < c.Limits.StreamsPerUser {
		return errors.New("config: limits_lcm.streams_per_user must be positive and streams_per_tenant at least as large")
	}
	if c.Limits.ReplayWindowSeconds < 60 || c.Limits.ReplayWindowSeconds > 3600 {
		return errors.New("config: limits_lcm.replay_window_seconds must be within [60, 3600]")
	}
	return nil
}

// Warnings lists accepted insecure opt-outs (logged at start).
func (c Config) Warnings() []string {
	w := c.Config.Warnings()
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey.allow_plaintext: stream traffic without TLS (development only)")
	}
	if c.ACME.AllowPlaintextDNS {
		w = append(w, "acme.allow_plaintext_dns: mock ACME/DNS without TLS (development only)")
	}
	return w
}

// ReplayWindow is the live-event replay window.
func (c Config) ReplayWindow() time.Duration {
	return time.Duration(c.Limits.ReplayWindowSeconds) * time.Second
}

// RenewalInterval is the scheduler tick.
func (c Config) RenewalInterval() time.Duration {
	return time.Duration(c.Renewal.IntervalSeconds) * time.Second
}

// LeaseDuration is how long a claimed job stays claimed.
func (c Config) LeaseDuration() time.Duration {
	return time.Duration(c.Renewal.LeaseSeconds) * time.Second
}

// LongLivedWindow is how far before expiry longer certificates are renewed.
func (c Config) LongLivedWindow() time.Duration {
	return time.Duration(c.Renewal.LongLivedDays) * 24 * time.Hour
}
