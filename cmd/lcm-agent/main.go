// Command lcm-agent is a small workload-side daemon that enrolls with the lcm
// certificate & SVID lifecycle module and then keeps the workload's certificate
// fresh, rotating on disk with no downtime.
//
// It dials the module over the Freya SPIFFE mTLS gRPC channel and drives
// lcmclient.RunAgent, which enrolls, writes cert/key/bundle to -dir, and renews
// via both a timer and the Agent.Watch stream.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/lcmclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type options struct {
	server      string
	spiffeID    string
	tenant      string
	token       string
	dir         string
	renewBefore time.Duration

	// File identity for the SPIFFE-mTLS dial, mirroring services/*/deploy/dev.yaml
	// identity.file (cert/key/bundle PEM paths). When all three are set the agent
	// dials with mutual TLS; otherwise it falls back to an insecure dial (dev only).
	identityCert   string
	identityKey    string
	identityBundle string
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("lcm-agent", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.server, "server", "", "lcm gRPC target (host:port), required")
	fs.StringVar(&o.spiffeID, "spiffe-id", "", "workload SPIFFE id to enroll, required")
	fs.StringVar(&o.tenant, "tenant", "", "tenant id the workload belongs to, required")
	fs.StringVar(&o.token, "token", "", "enrollment token (optional; auth-minted)")
	fs.StringVar(&o.dir, "dir", "", "output directory for cert/key/bundle, required")
	fs.DurationVar(&o.renewBefore, "renew-before", time.Hour, "renew when within this window of expiry")
	fs.StringVar(&o.identityCert, "identity-cert", "", "PEM cert for the SPIFFE-mTLS dial identity")
	fs.StringVar(&o.identityKey, "identity-key", "", "PEM key for the SPIFFE-mTLS dial identity")
	fs.StringVar(&o.identityBundle, "identity-bundle", "", "PEM trust bundle (roots) for the SPIFFE-mTLS dial")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	if o.server == "" {
		missing = append(missing, "-server")
	}
	if o.spiffeID == "" {
		missing = append(missing, "-spiffe-id")
	}
	if o.tenant == "" {
		missing = append(missing, "-tenant")
	}
	if o.dir == "" {
		missing = append(missing, "-dir")
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flags: %v", missing)
	}
	return o, nil
}

// dial builds a grpc.ClientConn to the lcm module.
//
// When -identity-cert/-identity-key/-identity-bundle are all supplied, it dials
// with mutual TLS using that file identity, mirroring the identity.file provider
// in services/*/deploy/dev.yaml. This is a straightforward file-based stand-in
// for the full Freya SPIFFE dial.
//
// TODO(spiffe): wire the real Freya SPIFFE-mTLS transport here. In-process,
// a workload obtains this connection from freya.App.Client(ctx, "lcm") (see
// services/notification/internal/app), which uses the rotating identity provider
// (identity/spiffe or identity/file) and the pool's SPIFFE-authenticating
// TransportCredentials, including SVID/peer-SPIFFE-id verification against the
// module's policy. The file-identity path below is a dev convenience; production
// should use the pooled Freya connection with live rotation and revocation
// checks rather than static PEM files loaded once at startup.
func dial(o options) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	switch {
	case o.identityCert != "" && o.identityKey != "" && o.identityBundle != "":
		cert, err := tls.LoadX509KeyPair(o.identityCert, o.identityKey)
		if err != nil {
			return nil, fmt.Errorf("load identity keypair: %w", err)
		}
		roots := x509.NewCertPool()
		pem, err := os.ReadFile(o.identityBundle)
		if err != nil {
			return nil, fmt.Errorf("read identity bundle: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("identity bundle contained no PEM certificates")
		}
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS13,
		})
	default:
		// Dev fallback: no file identity supplied. See the TODO above — this is
		// NOT the SPIFFE mTLS channel and must not be used in production.
		creds = insecure.NewCredentials()
	}
	return grpc.NewClient(o.server, grpc.WithTransportCredentials(creds))
}

func run(args []string) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := dial(o)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := lcmclient.New(conn)
	log.Info("lcm-agent: starting", "server", o.server, "spiffe_id", o.spiffeID, "dir", o.dir)

	err = client.RunAgent(ctx, lcmclient.AgentConfig{
		WriteDir:    o.dir,
		SpiffeID:    o.spiffeID,
		TenantID:    o.tenant,
		Token:       o.token,
		RenewBefore: o.renewBefore,
	}, log)
	if err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("lcm-agent: shutting down")
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lcm-agent:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
