package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/app"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/ca"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/config"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/csr"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/sealed"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// bootstrap prepares a deployment: it applies the migrations, checks the KEK
// (seal/open round trip), and — the production replacement for lcm-devca —
// ensures the ONE DB-sealed mesh root and mints a leaf SVID per service into
// -out (plus ca.pem, the trust bundle). Every leaf and lcm's own self-issued
// identity chain to this single root. Idempotent (EnsureCA reuses the sealed
// root; leaves are reissued) and never serves. Private keys are written only
// for the file-provider services during this dev bootstrap; in production
// workloads enroll and keep their key local.
func bootstrap(args []string) int {
	fs := flag.NewFlagSet("lcmsvc bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	out := fs.String("out", "", "write CA + per-service SVIDs to this directory (empty = migrate/KEK check only)")
	services := fs.String("services", "gateway,auth,lcm,notification", "comma-separated service names to mint leaves for")
	trustDomain := fs.String("trust-domain", "", "trust domain for the mesh root (default: config trust_domain)")
	ttl := fs.Duration("ttl", 12*time.Hour, "lifetime of each minted leaf SVID")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	td := *trustDomain
	if td == "" {
		td = cfg.Config.TrustDomain
	}
	ctx := context.Background()

	migrateDSN := cfg.DB.MigrateDSN
	if migrateDSN == "" {
		migrateDSN = cfg.DB.DSN
	}
	if err := store.Migrate(ctx, migrateDSN); err != nil {
		return fail(fmt.Errorf("migrate: %w", err))
	}
	st, err := store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns)
	if err != nil {
		return fail(err)
	}
	defer st.Close()

	kek, err := sealed.LoadKEK(cfg.KEK.Source, cfg.KEK.Path, cfg.KEK.Env)
	if err != nil {
		return fail(err)
	}
	env, err := sealed.NewEnvelope(kek)
	if err != nil {
		return fail(err)
	}
	res := struct {
		Migrated     bool     `json:"migrated"`
		KEK          string   `json:"kek"`
		RootSerial   string   `json:"root_serial,omitempty"`
		CertsWritten []string `json:"certs_written,omitempty"`
	}{Migrated: true, KEK: "ok"}
	if err := probeKEK(env); err != nil {
		res.KEK = err.Error()
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return 1
	}

	rp := repodb.New(st)
	authority := ca.New(rp, env)
	root, err := authority.EnsureCA(ctx, app.MeshTenantID, td)
	if err != nil {
		return fail(fmt.Errorf("ensure mesh CA: %w", err))
	}
	res.RootSerial = root.Serial
	// Enrolled workloads are issued through issue.Service, which needs a default
	// self-signed issuer bound to the mesh root. Ensure one (idempotent).
	if ierr := ensureDefaultIssuer(ctx, rp, td, root.ID); ierr != nil {
		return fail(fmt.Errorf("ensure default issuer: %w", ierr))
	}

	if *out != "" {
		if err := os.MkdirAll(*out, 0o755); err != nil { // #nosec G301 -- dev cert dir
			return fail(err)
		}
		for _, name := range strings.Split(*services, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			spiffeID := "spiffe://" + td + "/svc/" + name
			key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if gerr != nil {
				return fail(gerr)
			}
			der, _, serr := authority.SignLeaf(ctx, app.MeshTenantID, td, spiffeID, &key.PublicKey, *ttl)
			if serr != nil {
				return fail(fmt.Errorf("%s: %w", name, serr))
			}
			keyDER, merr := x509.MarshalPKCS8PrivateKey(key)
			if merr != nil {
				return fail(merr)
			}
			certPath := filepath.Join(*out, name+".pem")
			keyPath := filepath.Join(*out, name+".key")
			if werr := os.WriteFile(certPath, csr.EncodeCertPEM(der), 0o644); werr != nil { // #nosec G306 -- public leaf cert
				return fail(werr)
			}
			if werr := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); werr != nil {
				return fail(werr)
			}
			res.CertsWritten = append(res.CertsWritten, certPath)
			fmt.Fprintf(os.Stderr, "wrote %s %s (%s)\n", certPath, keyPath, spiffeID)
		}
		bundlePEM, berr := authority.Bundle(ctx, app.MeshTenantID, td)
		if berr != nil {
			return fail(berr)
		}
		caPath := filepath.Join(*out, "ca.pem")
		if werr := os.WriteFile(caPath, []byte(bundlePEM), 0o644); werr != nil { // #nosec G306 -- public trust bundle
			return fail(werr)
		}
		res.CertsWritten = append(res.CertsWritten, caPath)
		fmt.Fprintf(os.Stderr, "wrote %s (mesh trust bundle, root serial %s)\n", caPath, root.Serial)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return 0
}

// probeKEK seals and opens a probe value so a corrupted key surfaces before
// the first CA or secret is saved.
func probeKEK(e *sealed.Envelope) error {
	blob, err := e.Seal([]byte(`{"probe":true}`), sealed.ADCA("probe"))
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	if _, err := e.Open(blob, sealed.ADCA("probe")); err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return nil
}

// ensureDefaultIssuer creates a default self-signed issuer bound to the mesh
// root for the trust domain, if none exists yet.
func ensureDefaultIssuer(ctx context.Context, rp repo.Store, trustDomain, caID string) error {
	return rp.Atomic(ctx, app.MeshTenantID, func(tx repo.Store) error {
		if _, err := tx.DefaultIssuer(ctx, app.MeshTenantID, trustDomain); err == nil {
			return nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		name, err := meshIssuerName(ctx, tx, trustDomain)
		if err != nil {
			return err
		}
		id := caID
		return tx.InsertIssuer(ctx, store.Issuer{
			ID: store.NewID(), TenantID: app.MeshTenantID, Name: name, Type: "self_signed",
			TrustDomain: trustDomain, IsDefault: true, CAID: &id, Enabled: true, SettingsPublic: []byte("{}"),
		})
	})
}

// meshIssuerName is "mesh" for the first trust domain. Issuer names are unique
// per tenant, so after a trust domain change the new domain's issuer is
// "mesh-<trust domain>" (the old domain keeps "mesh").
func meshIssuerName(ctx context.Context, tx repo.Store, trustDomain string) (string, error) {
	after := ""
	for {
		page, err := tx.ListIssuers(ctx, app.MeshTenantID, after, 200)
		if err != nil {
			return "", err
		}
		for _, i := range page {
			if strings.EqualFold(i.Name, "mesh") {
				return "mesh-" + trustDomain, nil
			}
		}
		if len(page) < 200 {
			return "mesh", nil
		}
		after = page[len(page)-1].Name
	}
}
