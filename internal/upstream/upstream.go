package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/locnh/smtp-relay/internal/config"
)

const (
	defaultConnectTimeout = 10 * time.Second
	defaultCommandTimeout = 30 * time.Second
	defaultDataTimeout    = 2 * time.Minute
)

// Sender delivers mail to one upstream SMTP server. It is safe for concurrent
// use: every Send opens its own connection.
type Sender struct {
	cfg      config.UpstreamConfig
	ehloName string
	tlsCfg   *tls.Config
	password string
	connect  time.Duration
	command  time.Duration
	data     time.Duration
}

// New validates cfg and loads certificates once. ehloName is announced in EHLO.
func New(cfg config.UpstreamConfig, ehloName string) (*Sender, error) {
	switch cfg.TLS {
	case "tls", "starttls", "none":
	default:
		return nil, fmt.Errorf("upstream %q: unknown tls mode %q", cfg.Name, cfg.TLS)
	}
	s := &Sender{
		cfg:      cfg,
		ehloName: ehloName,
		connect:  orDefault(cfg.Timeouts.Connect, defaultConnectTimeout),
		command:  orDefault(cfg.Timeouts.Command, defaultCommandTimeout),
		data:     orDefault(cfg.Timeouts.Data, defaultDataTimeout),
	}

	opts := cfg.TLSOptions
	s.tlsCfg = &tls.Config{
		ServerName:         cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: read ca_file: %w", cfg.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream %q: ca_file contains no valid certificate", cfg.Name)
		}
		s.tlsCfg.RootCAs = pool
	}
	if (opts.ClientCertFile == "") != (opts.ClientKeyFile == "") {
		return nil, fmt.Errorf("upstream %q: client_cert_file and client_key_file must be set together", cfg.Name)
	}
	if opts.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.ClientCertFile, opts.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: load client certificate: %w", cfg.Name, err)
		}
		s.tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if a := cfg.Auth; a != nil {
		switch a.Mechanism {
		case "", "auto", "plain", "login":
		default:
			return nil, fmt.Errorf("upstream %q: unknown auth mechanism %q", cfg.Name, a.Mechanism)
		}
		s.password = a.Password.Reveal()
		if s.password == "" && a.PasswordFile != "" {
			b, err := os.ReadFile(a.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: read password_file: %w", cfg.Name, err)
			}
			s.password = strings.TrimRight(string(b), "\r\n")
		}
	}
	return s, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Name returns the configured upstream name.
func (s *Sender) Name() string { return s.cfg.Name }

type stage int

const (
	stageDial stage = iota
	stageGreeting
	stageStartTLS
	stageAuth
	stageMail
)

// Send delivers one message over a fresh connection. It returns nil or *Error.
func (s *Sender) Send(ctx context.Context, from string, to []string, data []byte) error {
	if err := validateAddresses(from, to); err != nil {
		return &Error{Class: ClassOther, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return ctxError(err)
	}

	st := stageDial
	err := s.send(ctx, &st, from, to, data)
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		ue := ctxError(cerr)
		ue.Err = fmt.Errorf("%w (%v)", cerr, err)
		return ue
	}
	return classify(st, err)
}

func validateAddresses(from string, to []string) error {
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	for _, a := range append([]string{from}, to...) {
		if strings.ContainsAny(a, "\r\n") {
			return errors.New("address contains CR or LF")
		}
	}
	return nil
}

func ctxError(err error) *Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Class: ClassTimeout, Err: err}
	}
	return &Error{Class: ClassOther, Err: err}
}

func (s *Sender) send(ctx context.Context, st *stage, from string, to []string, data []byte) (err error) {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	dialer := net.Dialer{Timeout: s.connect}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	// conn stays the raw TCP connection: deadlines set on it still apply after
	// it is wrapped by TLS.
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	deadline := func(d time.Duration) { _ = conn.SetDeadline(time.Now().Add(d)) }

	var c *smtp.Client
	if s.cfg.TLS == "tls" {
		*st = stageStartTLS
		deadline(s.connect)
		tc := tls.Client(conn, s.tlsCfg.Clone())
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		*st = stageGreeting
		deadline(s.command)
		if c, err = smtp.NewClient(tc, s.cfg.Host); err != nil {
			return err
		}
	} else {
		*st = stageGreeting
		deadline(s.command)
		if c, err = smtp.NewClient(conn, s.cfg.Host); err != nil {
			return err
		}
	}

	// quit is only attempted when the protocol is still in sync; after I/O or
	// TLS failures the connection is just closed.
	defer func() {
		var te *textproto.Error
		var ue *Error
		if err == nil || errors.As(err, &te) || errors.As(err, &ue) {
			deadline(s.command)
			_ = c.Quit()
		}
		_ = c.Close()
	}()

	deadline(s.command)
	if err := c.Hello(s.ehloName); err != nil {
		return err
	}

	if s.cfg.TLS == "starttls" {
		*st = stageStartTLS
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return &Error{Class: ClassTLS, Err: errors.New("server does not advertise STARTTLS")}
		}
		// The STARTTLS command, the handshake and the second EHLO are all
		// part of establishing the encrypted channel.
		deadline(s.connect)
		if err := c.StartTLS(s.tlsCfg.Clone()); err != nil {
			return err
		}
	}

	if s.cfg.Auth != nil {
		*st = stageAuth
		deadline(s.command)
		a, err := s.authenticator(c)
		if err != nil {
			return err
		}
		if err := c.Auth(a); err != nil {
			return err
		}
	}

	*st = stageMail
	deadline(s.command)
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		deadline(s.command)
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}

	deadline(s.command)
	w, err := c.Data()
	if err != nil {
		return err
	}
	deadline(s.data)
	if _, err := w.Write(data); err != nil {
		return err
	}
	return w.Close()
}

// authenticator picks the mechanism and fails locally, before sending
// anything, when the server cannot satisfy the configured one.
func (s *Sender) authenticator(c *smtp.Client) (smtp.Auth, error) {
	a := s.cfg.Auth
	ok, params := c.Extension("AUTH")
	if !ok {
		return nil, &Error{Class: ClassAuth, Err: errors.New("authentication configured but server does not advertise AUTH")}
	}
	advertised := map[string]bool{}
	for _, m := range strings.Fields(strings.ToUpper(params)) {
		advertised[m] = true
	}

	mech := strings.ToLower(a.Mechanism)
	switch mech {
	case "", "auto":
		mech = "login"
		if advertised["PLAIN"] {
			mech = "plain"
		}
	}
	if !advertised[strings.ToUpper(mech)] {
		return nil, &Error{Class: ClassAuth, Err: fmt.Errorf("server does not advertise AUTH %s", strings.ToUpper(mech))}
	}
	if mech == "plain" {
		return &plainAuth{a.Username, s.password, a.AllowInsecureAuth}, nil
	}
	return &loginAuth{username: a.Username, password: s.password, allowInsecure: a.AllowInsecureAuth}, nil
}

// isTLSAlert detects an alert sent by the peer; crypto/tls does not export the
// alert type, only wraps it in a *net.OpError with Op "remote error".
func isTLSAlert(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error"
}

func classify(st stage, err error) *Error {
	var ue *Error
	if errors.As(err, &ue) {
		return ue
	}

	var te *textproto.Error
	hasReply := errors.As(err, &te)
	e := &Error{Err: err}
	if hasReply {
		e.Code, e.Message = te.Code, te.Msg
	}

	var ne net.Error
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		e.Class = ClassTimeout
	// With TLS 1.3 a rejected client certificate surfaces as an alert on the
	// first read after the handshake, not as a handshake error.
	case isTLSAlert(err) || errors.As(err, &certErr):
		e.Class = ClassTLS
	case st == stageDial:
		e.Class = ClassConnect
	case st == stageStartTLS:
		e.Class = ClassTLS
	case st == stageAuth && hasReply:
		e.Class = ClassAuth
	case hasReply && te.Code >= 400 && te.Code < 500:
		e.Class = ClassSMTP4xx
	case hasReply && te.Code >= 500 && te.Code < 600:
		e.Class = ClassSMTP5xx
	default:
		e.Class = ClassOther
	}
	if errors.Is(err, io.EOF) && e.Class == ClassOther {
		e.Err = fmt.Errorf("connection closed by server: %w", err)
	}
	return e
}
