package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/locnh/smtp-relay/internal/maillog"
	"github.com/locnh/smtp-relay/internal/relay"
)

// Deliverer forwards an accepted message upstream. *relay.Relay implements it.
type Deliverer interface {
	Deliver(ctx context.Context, msg *relay.Message) relay.Result
}

// Events is implemented by the app (logging, metrics, quota). Implementations
// must be safe for concurrent use and must not block.
type Events interface {
	// MessageRejected is called for a mail refused before DATA completed:
	// sender_denied, null_sender or size_exceeded.
	MessageRejected(reason string)
	ConnAccepted(listener string)
	ConnClosed(listener string)
	// ConnRejected result is denied_network or rejected_limit.
	ConnRejected(listener, result string)
	// MessageReceived is called once DATA has been read completely.
	MessageReceived(size int)
	// MessageDone is called exactly once per mail that reached the end of
	// DATA, after delivery was attempted.
	MessageDone(s maillog.Summary, res relay.Result)
}

// NopEvents ignores all events.
type NopEvents struct{}

func (NopEvents) MessageRejected(string)                    {}
func (NopEvents) ConnAccepted(string)                       {}
func (NopEvents) ConnClosed(string)                         {}
func (NopEvents) ConnRejected(string, string)               {}
func (NopEvents) MessageReceived(int)                       {}
func (NopEvents) MessageDone(maillog.Summary, relay.Result) {}

// Config holds everything New needs.
type Config struct {
	Server    config.ServerConfig
	Policy    *Policy
	Deliverer Deliverer
	Events    Events // nil means NopEvents
	Log       zerolog.Logger
	Hostname  string        // EHLO name and banner
	NewID     func() string // defaults to uuid.NewString
}

type listenerState struct {
	name string
	cfg  config.ListenConfig
	smtp *smtp.Server
	tls  *tls.Config
	raw  net.Listener
}

// Server is the SMTP receiving side: one go-smtp server per listener sharing
// one admission gate.
type Server struct {
	policy      *Policy
	deliverer   Deliverer
	events      Events
	log         zerolog.Logger
	newID       func() string
	dataTimeout time.Duration
	drainGrace  time.Duration

	gate      *gate
	listeners []*listenerState
	notAfter  time.Time
	hasCert   bool

	// ctx is handed to Deliver; Shutdown cancels it only once its own ctx expires.
	ctx    context.Context
	cancel context.CancelFunc

	closing atomic.Bool
	wg      sync.WaitGroup
	// inflight counts Session.Data calls, including their MessageDone.
	inflight atomic.Int64
}

// defaultDrainGrace bounds how long Shutdown waits, after force-closing, for
// deliveries to observe the cancelled context and finish.
const defaultDrainGrace = 5 * time.Second

// New validates the configuration (including loading the TLS keypair when a
// listener needs it) and builds the servers. It binds nothing.
func New(c Config) (*Server, error) {
	if c.Policy == nil || c.Deliverer == nil {
		return nil, errors.New("server: Policy and Deliverer are required")
	}
	if c.Events == nil {
		c.Events = NopEvents{}
	}
	if c.NewID == nil {
		c.NewID = uuid.NewString
	}
	sc := c.Server
	if sc.Limits.MaxConnections == 0 || sc.Limits.MaxConnections < -1 {
		return nil, errors.New("server: max_connections must be -1 or >= 1")
	}
	if sc.Limits.MaxLineLength < 1000 {
		return nil, errors.New("server: max_line_length must be >= 1000")
	}

	s := &Server{
		policy:      c.Policy,
		deliverer:   c.Deliverer,
		events:      c.Events,
		log:         c.Log,
		newID:       c.NewID,
		dataTimeout: sc.Timeouts.Data,
		drainGrace:  defaultDrainGrace,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.gate = newGate(c.Policy, sc.Limits.MaxConnections, c.Events, c.Log)

	needTLS := false
	for _, l := range sc.Listen {
		switch l.TLS {
		case "none", "":
		case "starttls", "tls":
			needTLS = true
		default:
			return nil, fmt.Errorf("server: listener %s: unknown tls mode %q", l.Address, l.TLS)
		}
	}
	var tlsCfg *tls.Config
	if needTLS {
		cert, err := tls.LoadX509KeyPair(sc.TLS.CertFile, sc.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("server: load tls keypair: %w", err)
		}
		if tlsCfg, err = tlsConfigFor(sc.TLS.Profile, cert); err != nil {
			return nil, fmt.Errorf("server: %w", err)
		}
		leaf := cert.Leaf
		if leaf == nil && len(cert.Certificate) > 0 {
			if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				return nil, fmt.Errorf("server: parse certificate: %w", err)
			}
		}
		if leaf != nil {
			s.notAfter, s.hasCert = leaf.NotAfter, true
		}
	}

	domain := c.Hostname
	if sc.WelcomeMessage != "" {
		// go-smtp has no banner text option; Domain is the only part of the 220 greeting we control.
		domain += " " + sc.WelcomeMessage
	}
	for _, l := range sc.Listen {
		ls := &listenerState{name: l.Address, cfg: l}
		srv := smtp.NewServer(&backend{srv: s, listener: ls.name, forceTLS: l.ForceTLS && l.TLS == "starttls"})
		srv.Network = "tcp"
		srv.Domain = domain
		srv.ReadTimeout = sc.Timeouts.Read
		srv.WriteTimeout = sc.Timeouts.Write
		srv.MaxMessageBytes = sc.Limits.MaxMessageSize
		srv.MaxRecipients = sc.Limits.MaxRecipients
		// go-smtp's default (2000) would also reject long DATA lines, which a
		// transparent relay must forward. Config validation guarantees >= 1000.
		srv.MaxLineLength = sc.Limits.MaxLineLength
		srv.EnableSMTPUTF8 = true
		srv.ErrorLog = zlogger{c.Log}
		if l.TLS == "starttls" {
			srv.TLSConfig = tlsCfg
		}
		if l.TLS == "tls" {
			ls.tls = tlsCfg
		}
		ls.smtp = srv
		s.listeners = append(s.listeners, ls)
	}
	return s, nil
}

// Start binds every listener before serving any, so a failure leaves nothing open.
func (s *Server) Start() error {
	for _, ls := range s.listeners {
		l, err := net.Listen("tcp", ls.cfg.Address)
		if err != nil {
			s.closeRaw()
			return fmt.Errorf("server: listen %s: %w", ls.cfg.Address, err)
		}
		ls.raw = l
	}
	for _, ls := range s.listeners {
		var l net.Listener = s.gate.wrap(ls.name, ls.raw)
		if ls.tls != nil {
			l = tls.NewListener(l, ls.tls)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := ls.smtp.Serve(l); err != nil && !s.closing.Load() && !errors.Is(err, net.ErrClosed) {
				s.log.Error().Err(err).Str("listener", ls.name).Msg("listener stopped")
			}
		}()
		s.log.Info().Str("listener", ls.name).Str("tls", ls.cfg.TLS).Str("addr", ls.raw.Addr().String()).Msg("listening")
	}
	return nil
}

func (s *Server) closeRaw() {
	for _, ls := range s.listeners {
		if ls.raw != nil {
			_ = ls.raw.Close()
		}
	}
}

// Addrs returns the bound addresses in configuration order.
func (s *Server) Addrs() []net.Addr {
	var out []net.Addr
	for _, ls := range s.listeners {
		if ls.raw != nil {
			out = append(out, ls.raw.Addr())
		}
	}
	return out
}

// CertNotAfter returns the server certificate expiry, if a certificate is loaded.
func (s *Server) CertNotAfter() (time.Time, bool) { return s.notAfter, s.hasCert }

// Shutdown stops accepting, closes idle connections and waits for in-flight
// mails. When ctx expires the remaining connections are closed, delivery is
// cancelled and Shutdown waits a short grace period for deliveries to unwind.
//
// Once Shutdown returns nil, or returns after the grace period, no further
// MessageDone fires. The exception is a Deliverer that ignores its context for
// longer than the grace period; that is logged with the number of leaked
// deliveries. Calling Shutdown again returns nil.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closing.Store(true)
	s.closeRaw()

	errs := make(chan error, len(s.listeners))
	for _, ls := range s.listeners {
		go func() { errs <- ls.smtp.Shutdown(ctx) }()
	}

	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var all []error
	timedOut := false
	for pending := len(s.listeners); pending > 0; {
		select {
		case err := <-errs:
			pending--
			switch {
			case err == nil, errors.Is(err, net.ErrClosed), errors.Is(err, smtp.ErrServerClosed):
			case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
				timedOut = true
			default:
				all = append(all, err)
			}
		case <-tick.C:
			s.gate.closeIdle()
		}
	}
	if timedOut {
		s.cancel()
		s.gate.closeAll()
		all = append(all, ctx.Err())
	}
	s.wg.Wait()
	if timedOut {
		s.waitInflight()
	}
	s.cancel()
	return errors.Join(all...)
}

// waitInflight waits, within one grace period, for the force-closed
// connections to be released and then for running deliveries to finish.
func (s *Server) waitInflight() {
	deadline := time.Now().Add(s.drainGrace)
	for s.gate.active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for s.inflight.Load() > 0 {
		if time.Now().After(deadline) {
			s.log.Warn().Int64("leaked_deliveries", s.inflight.Load()).
				Msg("deliveries still running after shutdown grace period")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type zlogger struct{ l zerolog.Logger }

// go-smtp reports routine per-connection trouble (failed handshakes, resets,
// EOF-like errors) through this logger; only panics and accept failures matter.
func (z zlogger) Printf(format string, v ...interface{}) { z.log(fmt.Sprintf(format, v...)) }
func (z zlogger) Println(v ...interface{})               { z.log(strings.TrimSpace(fmt.Sprintln(v...))) }

func (z zlogger) log(msg string) {
	switch {
	case strings.Contains(msg, "panic"):
		z.l.Error().Msg(msg)
	case strings.Contains(msg, "accept error"):
		z.l.Warn().Msg(msg)
	default:
		z.l.Debug().Msg(msg)
	}
}
