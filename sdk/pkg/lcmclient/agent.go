package lcmclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// File names written into AgentConfig.WriteDir.
const (
	certFile   = "tls.crt"
	keyFile    = "tls.key"
	chainFile  = "chain.pem"
	bundleFile = "bundle.pem"
)

// AgentConfig configures RunAgent, the reusable auto-renew loop.
type AgentConfig struct {
	WriteDir    string        // directory the cert/key/bundle are written to
	SpiffeID    string        // workload SPIFFE id to enroll/renew
	TenantID    string        // tenant the workload belongs to
	Token       string        // optional enrollment token (auth-minted)
	RenewBefore time.Duration // renew when within this window of NotAfter (default 1h)
}

// materialize writes a Bundle's cert/key/chain/bundle into WriteDir atomically.
// The private key is 0600; everything else is 0644. Files are written to a temp
// path and renamed so a reader never sees a half-written file, and so a workload
// rotates without downtime. KeyPEM is written only when present (the module
// returns it once, when it generated the key).
func (cfg AgentConfig) materialize(b *Bundle) error {
	if b == nil {
		return errors.New("lcmclient: nil bundle")
	}
	if cfg.WriteDir == "" {
		return errors.New("lcmclient: empty WriteDir")
	}
	if err := os.MkdirAll(cfg.WriteDir, 0o700); err != nil {
		return err
	}
	writes := []struct {
		name string
		data string
		mode os.FileMode
	}{
		{certFile, b.CertPEM, 0o644},
		{chainFile, b.ChainPEM, 0o644},
		{bundleFile, b.BundlePEM, 0o644},
	}
	if b.KeyPEM != "" {
		writes = append(writes, struct {
			name string
			data string
			mode os.FileMode
		}{keyFile, b.KeyPEM, 0o600})
	}
	for _, w := range writes {
		if w.data == "" {
			continue
		}
		if err := atomicWrite(filepath.Join(cfg.WriteDir, w.name), []byte(w.data), w.mode); err != nil {
			return fmt.Errorf("lcmclient: write %s: %w", w.name, err)
		}
	}
	return nil
}

// atomicWrite writes data to path via a temp file in the same directory followed
// by a rename, so concurrent readers see either the old or the new whole file.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RunAgent enrolls (or renews an existing cert), writes the material to
// cfg.WriteDir, then keeps the workload's certificate fresh until ctx is done.
// It runs two concurrent drivers:
//
//   - a renewal timer that renews when within cfg.RenewBefore of NotAfter and
//     rewrites the material atomically;
//   - the Agent.Watch stream, which triggers an out-of-band renewal whenever the
//     module reports the workload's cert was renewed/revoked, and which is
//     reconnected with capped exponential backoff on error.
//
// RunAgent returns nil on ctx cancellation and an error only for an
// unrecoverable initial enrollment failure.
func (c *Client) RunAgent(ctx context.Context, cfg AgentConfig, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = time.Hour
	}

	// Initial acquisition: enroll to obtain the first SVID and its cert id.
	b, err := c.Enroll(ctx, EnrollRequest{
		TenantID:        cfg.TenantID,
		SpiffeID:        cfg.SpiffeID,
		EnrollmentToken: cfg.Token,
	})
	if err != nil {
		return fmt.Errorf("lcmclient: enroll: %w", err)
	}
	if err := cfg.materialize(b); err != nil {
		return err
	}
	certID := b.Serial // renew keys off the certificate id/serial the module returned
	notAfter := b.NotAfter
	log.Info("lcm-agent: enrolled", "spiffe_id", cfg.SpiffeID, "serial", b.Serial, "not_after", notAfter)

	// renew performs one renewal and rewrites material, updating notAfter/certID.
	renew := func(reason string) {
		if certID == "" {
			return
		}
		nb, err := c.RenewTenant(ctx, cfg.TenantID, certID)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("lcm-agent: renew failed", "reason", reason, "err", err)
			return
		}
		if err := cfg.materialize(nb); err != nil {
			log.Error("lcm-agent: write renewed material failed", "err", err)
			return
		}
		if nb.Serial != "" {
			certID = nb.Serial
		}
		notAfter = nb.NotAfter
		log.Info("lcm-agent: renewed", "reason", reason, "serial", nb.Serial, "not_after", notAfter)
	}

	// Trigger channel: the Watch driver pokes the renewal loop.
	trigger := make(chan struct{}, 1)
	poke := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	// Watch driver: reconnect with backoff, poke on relevant updates.
	go c.watchLoop(ctx, cfg, poke, log)

	// Renewal loop: fire when within RenewBefore of expiry, or on a poke.
	timer := time.NewTimer(untilRenew(notAfter, cfg.RenewBefore))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
			renew("watch")
		case <-timer.C:
			renew("timer")
		}
		// Reschedule against the (possibly updated) expiry.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(untilRenew(notAfter, cfg.RenewBefore))
	}
}

// untilRenew returns how long to wait before renewing a cert expiring at
// notAfter, given a renewBefore window. It is clamped to a small minimum so the
// loop never busy-spins, and defaults to renewBefore when notAfter is unknown.
func untilRenew(notAfter time.Time, renewBefore time.Duration) time.Duration {
	const minWait = 5 * time.Second
	if notAfter.IsZero() {
		return renewBefore
	}
	d := time.Until(notAfter) - renewBefore
	if d < minWait {
		return minWait
	}
	return d
}

// watchLoop keeps an Agent.Watch stream open, reconnecting with capped
// exponential backoff, and calls poke on each update that concerns this workload
// (or on any update — the renewal loop is idempotent and cheap to poke).
func (c *Client) watchLoop(ctx context.Context, cfg AgentConfig, poke func(), log *slog.Logger) {
	const (
		baseBackoff = 500 * time.Millisecond
		maxBackoff  = 30 * time.Second
	)
	backoff := baseBackoff
	var lastEventID string
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.WatchTenant(ctx, cfg.TenantID, lastEventID, func(u Update) {
			if u.SpiffeID != "" && cfg.SpiffeID != "" && u.SpiffeID != cfg.SpiffeID {
				return
			}
			if u.Type == "renewed" || u.Type == "revoked" || u.Type == "issued" {
				poke()
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("lcm-agent: watch stream ended, reconnecting", "err", err, "backoff", backoff)
		} else {
			log.Debug("lcm-agent: watch stream ended cleanly, reconnecting")
			backoff = baseBackoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}
