package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/locnh/smtp-relay/internal/app"
	"github.com/locnh/smtp-relay/internal/config"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smtp-relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the YAML configuration file")
	checkConfig := fs.Bool("check-config", false, "validate the configuration and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "smtp-relay/%s (%s)\n", version, buildTime)
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "smtp-relay: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "smtp-relay: -config is required")
		fs.Usage()
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			fmt.Fprintf(stderr, "smtp-relay: invalid configuration:\n%v\n", err)
		} else {
			fmt.Fprintf(stderr, "smtp-relay: %v\n", err)
		}
		return 1
	}

	if *checkConfig {
		for _, w := range cfg.Warnings() {
			fmt.Fprintln(stdout, "warning: "+w)
		}
		fmt.Fprintln(stdout, "config OK")
		return 0
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(stderr, "smtp-relay: %v\n", err)
		return 1
	}
	return 0
}

// run starts the relay and blocks until SIGINT/SIGTERM. Configuration
// warnings are logged by the app itself.
func run(cfg *config.Config) error {
	a, err := app.New(cfg, version)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}
