// Package app wires the finished packages into a running relay.
package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/locnh/smtp-relay/internal/logging"
	"github.com/locnh/smtp-relay/internal/metrics"
	"github.com/locnh/smtp-relay/internal/quota"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/server"
	"github.com/locnh/smtp-relay/internal/upstream"
)

const (
	logDirMode      = 0o750
	metricsShutdown = 5 * time.Second
)

// App owns every component of a running relay. Build it with New and start it
// with Run, which always releases everything it owns before returning.
type App struct {
	cfg *config.Config

	logger  *logging.Logger
	log     zerolog.Logger
	quota   *quota.Manager // nil when no upstream has a quota
	metrics *metrics.Metrics
	metSrv  *metrics.Server // nil when metrics are disabled
	srv     *server.Server

	ready   atomic.Bool
	started atomic.Bool

	stopQuota context.CancelFunc
	quotaDone chan struct{}

	mu    sync.Mutex
	addrs []net.Addr
}

// New builds every component without binding any port. On error everything
// already created is released.
func New(cfg *config.Config, version string) (*App, error) {
	a := &App{cfg: cfg}
	if err := a.build(version); err != nil {
		a.release()
		return nil, err
	}
	return a, nil
}

func (a *App) build(version string) error {
	cfg := a.cfg

	if cfg.Logging.Output == "file" && cfg.Logging.File.Path != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Logging.File.Path), logDirMode); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
	}
	logger, err := logging.New(cfg.Logging)
	if err != nil {
		return err
	}
	a.logger, a.log = logger, logger.Zerolog()

	for _, w := range cfg.Warnings() {
		a.log.Warn().Msg(w)
	}

	if q := quotaOptions(cfg); len(q) > 0 {
		a.quota, err = quota.New(quota.Options{Upstreams: q, StateFile: cfg.State.File, Log: a.log})
		if err != nil {
			return err
		}
	}

	senders := make([]relay.Sender, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		s, err := upstream.New(u, cfg.Server.Hostname)
		if err != nil {
			return err
		}
		senders = append(senders, s)
	}

	// A nil *quota.Manager must not be wrapped in a non-nil interface.
	var qs metrics.QuotaSource
	if a.quota != nil {
		qs = a.quota
	}
	a.metrics = metrics.New(version, qs)
	for _, u := range cfg.Upstreams {
		if u.TLSOptions.ClientCertFile == "" {
			continue
		}
		notAfter, err := certNotAfter(u.TLSOptions.ClientCertFile)
		if err != nil {
			return fmt.Errorf("upstream %q client certificate: %w", u.Name, err)
		}
		a.metrics.SetCertExpiry("upstream:"+u.Name, notAfter)
	}

	rl := relay.New(senders, observer{m: a.metrics, log: a.log})
	a.srv, err = server.New(server.Config{
		Server:    cfg.Server,
		Policy:    server.NewPolicy(cfg.Access),
		Deliverer: rl,
		Events:    events{m: a.metrics, q: a.quota, log: a.log},
		Log:       a.log,
		Hostname:  cfg.Server.Hostname,
	})
	if err != nil {
		return err
	}
	if notAfter, ok := a.srv.CertNotAfter(); ok {
		a.metrics.SetCertExpiry("server", notAfter)
	}

	if cfg.Metrics.Enabled {
		a.metSrv = metrics.NewServer(cfg.Metrics.Listen, cfg.Metrics.Path, a.metrics, a.ready.Load)
	}
	return nil
}

func quotaOptions(cfg *config.Config) []quota.UpstreamQuota {
	var out []quota.UpstreamQuota
	for _, u := range cfg.Upstreams {
		if u.Quota != nil {
			out = append(out, quota.UpstreamQuota{Name: u.Name, Limit: u.Quota.Limit, Window: u.Quota.Window})
		}
	}
	return out
}

// Addrs returns the bound SMTP listener addresses; empty until Run has bound them.
func (a *App) Addrs() []net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]net.Addr(nil), a.addrs...)
}

// MetricsAddr returns the bound metrics address, or nil when metrics are
// disabled or not started yet.
func (a *App) MetricsAddr() net.Addr {
	if a.metSrv == nil {
		return nil
	}
	return a.metSrv.Addr()
}

// Run starts every component and blocks until ctx is cancelled, then shuts
// down in order. It returns nil on a clean shutdown. An App can run only once.
func (a *App) Run(ctx context.Context) error {
	if !a.started.CompareAndSwap(false, true) {
		return errors.New("app: already run")
	}

	if err := a.srv.Start(); err != nil {
		a.stop(false, false)
		return err
	}
	a.mu.Lock()
	a.addrs = a.srv.Addrs()
	a.mu.Unlock()

	a.startQuota()

	a.ready.Store(true)
	if a.metSrv != nil {
		if err := a.metSrv.Start(); err != nil {
			_ = a.stop(true, false)
			return err
		}
	}
	a.log.Info().Msg("started")

	<-ctx.Done()
	a.log.Info().Msg("shutting down")
	return a.stop(true, a.metSrv != nil)
}

func (a *App) startQuota() {
	a.quotaDone = make(chan struct{})
	if a.quota == nil {
		close(a.quotaDone)
		return
	}
	var ctx context.Context
	ctx, a.stopQuota = context.WithCancel(context.Background())
	go func() {
		defer close(a.quotaDone)
		a.quota.Run(ctx)
	}()
}

// stop shuts components down in the order required by spec 6.6.
func (a *App) stop(serverStarted, metricsStarted bool) error {
	a.ready.Store(false)
	var errs []error

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.Server.Timeouts.Shutdown)
	if err := a.srv.Shutdown(ctx); err != nil {
		a.log.Warn().Err(err).Msg("server shutdown did not complete cleanly")
		errs = append(errs, fmt.Errorf("server shutdown: %w", err))
	}
	cancel()

	if a.stopQuota != nil {
		a.stopQuota()
		<-a.quotaDone
	}
	if a.quota != nil {
		if err := a.quota.Close(); err != nil {
			a.log.Error().Err(err).Msg("final quota state flush failed")
		}
	}

	if metricsStarted {
		mctx, mcancel := context.WithTimeout(context.Background(), metricsShutdown)
		if err := a.metSrv.Shutdown(mctx); err != nil {
			a.log.Warn().Err(err).Msg("metrics server shutdown failed")
		}
		mcancel()
	}

	if serverStarted {
		a.log.Info().Msg("stopped")
	}
	if err := a.logger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close log: %w", err))
	}
	return errors.Join(errs...)
}

// release frees what New had built when it fails part-way.
func (a *App) release() {
	if a.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = a.srv.Shutdown(ctx)
		cancel()
	}
	if a.quota != nil {
		_ = a.quota.Close()
	}
	if a.logger != nil {
		_ = a.logger.Close()
	}
}

// certNotAfter returns the expiry of the first certificate in a PEM file.
func certNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return time.Time{}, errors.New("no certificate found in PEM file")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return cert.NotAfter, nil
	}
}
