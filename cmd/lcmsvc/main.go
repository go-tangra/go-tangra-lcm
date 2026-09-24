// Command lcmsvc runs the lcm module (default) or prepares a deployment:
// `lcmsvc bootstrap -config deploy/dev.yaml` applies the migrations, checks the
// KEK and prints the dependency health.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/app"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/config"
	"github.com/go-tangra/go-tangra-lcm/v4/ui"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		os.Exit(bootstrap(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("lcmsvc", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations on start")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := app.Options{Migrate: !*noMigrate, Register: app.Wire}
	if remote, ok := ui.Remote(); ok {
		opts.Remote = remote
	}
	a, err := app.Build(ctx, cfg, opts)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if ep, err := a.Freya.HTTP().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "lcmsvc: browser API (via gateway) on", ep.String())
	}
	if ep, err := a.Freya.GRPC().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "lcmsvc: grpc listening on", ep.String())
	}
	if err := a.Run(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "lcmsvc:", err)
	return 1
}
