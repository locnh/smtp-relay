package upstream_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/upstream"
)

var _ relay.Sender = (*upstream.Sender)(nil)

const (
	ehlo = "relay.home.lan"
	user = "relay-user"
	pass = "S3cr3t-p4ss!"
)

var testMsg = []byte("From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n")

func baseCfg(port int, mode string) config.UpstreamConfig {
	return config.UpstreamConfig{
		Name: "fake",
		Host: "127.0.0.1",
		Port: port,
		TLS:  mode,
		Timeouts: config.UpstreamTimeouts{
			Connect: 2 * time.Second,
			Command: 2 * time.Second,
			Data:    2 * time.Second,
		},
	}
}

func withAuth(cfg config.UpstreamConfig, mech string, insecure bool) config.UpstreamConfig {
	cfg.Auth = &config.AuthConfig{Mechanism: mech, Username: user, Password: config.Secret(pass), AllowInsecureAuth: insecure}
	return cfg
}

func send(t *testing.T, cfg config.UpstreamConfig) error {
	t.Helper()
	return sendCtx(t, context.Background(), cfg)
}

func sendCtx(t *testing.T, ctx context.Context, cfg config.UpstreamConfig) error {
	t.Helper()
	s, err := upstream.New(cfg, ehlo)
	require.NoError(t, err)
	return s.Send(ctx, "a@example.com", []string{"b@example.com"}, testMsg)
}

func requireClass(t *testing.T, err error, want upstream.Class) *upstream.Error {
	t.Helper()
	require.Error(t, err)
	var ue *upstream.Error
	require.ErrorAs(t, err, &ue, "Send must return *upstream.Error")
	require.Equal(t, want, ue.Class, "err: %v", err)
	assert.NotContains(t, err.Error(), pass)
	return ue
}

type pki struct {
	ca         *testCA
	serverTLS  *tls.Config
	serverCert tls.Certificate
	caFile     string
}

func newPKI(t *testing.T) pki {
	ca := newTestCA(t, "test-ca")
	cert, _, _ := ca.issue(t, "fake.test")
	return pki{
		ca:         ca,
		serverCert: cert,
		serverTLS:  &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		caFile:     writeFile(t, "ca.pem", ca.pem),
	}
}

func TestSend_EHLONameAndRoundTrip(t *testing.T) {
	p := newPKI(t)
	srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN LOGIN", User: user, Pass: pass})
	cfg := withAuth(baseCfg(srv.port(), "starttls"), "auto", false)
	cfg.TLSOptions.CAFile = p.caFile

	require.NoError(t, send(t, cfg))

	// Hello is sent before STARTTLS and again after it, both with our name.
	assert.Equal(t, []string{ehlo, ehlo}, srv.ehloNames())
	got := srv.received()
	assert.True(t, got.Delivered)
	assert.Equal(t, "<a@example.com>", got.MailFrom)
	assert.Equal(t, []string{"<b@example.com>"}, got.Rcpts)
	assert.Equal(t, testMsg, got.Data)
}

func TestSend_ImplicitTLS_EHLOName(t *testing.T) {
	p := newPKI(t)
	srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, Implicit: true, User: user, Pass: pass})
	cfg := baseCfg(srv.port(), "tls")
	cfg.TLSOptions.CAFile = p.caFile

	require.NoError(t, send(t, cfg))
	assert.Equal(t, []string{ehlo}, srv.ehloNames())
	assert.True(t, srv.received().Delivered)
}

func TestSend_NoneNoAuth(t *testing.T) {
	srv := startServer(t, serverOpts{})
	require.NoError(t, send(t, baseCfg(srv.port(), "none")))
	assert.Equal(t, []string{ehlo}, srv.ehloNames())
	assert.True(t, srv.received().Delivered)
	assert.False(t, srv.sawAny("AUTH", "STARTTLS"))
}

func TestSend_AuthMechanisms(t *testing.T) {
	tests := []struct {
		name      string
		advertise string
		mech      string
		wantAuth  string
		wantClass upstream.Class
	}{
		{"auto picks PLAIN when advertised", "PLAIN LOGIN", "auto", "AUTH PLAIN", upstream.ClassNone},
		{"auto picks PLAIN when only PLAIN", "PLAIN", "auto", "AUTH PLAIN", upstream.ClassNone},
		{"auto falls back to LOGIN", "LOGIN", "auto", "AUTH LOGIN", upstream.ClassNone},
		{"explicit login even if PLAIN offered", "PLAIN LOGIN", "login", "AUTH LOGIN", upstream.ClassNone},
		{"explicit plain", "PLAIN LOGIN", "plain", "AUTH PLAIN", upstream.ClassNone},
		{"explicit plain not advertised", "LOGIN", "plain", "", upstream.ClassAuth},
		{"explicit login not advertised", "PLAIN", "login", "", upstream.ClassAuth},
		{"AUTH not advertised at all", "", "auto", "", upstream.ClassAuth},
		{"auto with only unknown mechanism", "XOAUTH2", "auto", "", upstream.ClassAuth},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPKI(t)
			srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: tc.advertise, User: user, Pass: pass})
			cfg := withAuth(baseCfg(srv.port(), "starttls"), tc.mech, false)
			cfg.TLSOptions.CAFile = p.caFile

			err := send(t, cfg)
			if tc.wantClass != upstream.ClassNone {
				requireClass(t, err, tc.wantClass)
				assert.False(t, srv.sawAny("AUTH", "MAIL"), "must fail locally before AUTH/MAIL: %v", srv.commands())
				return
			}
			require.NoError(t, err)
			assert.True(t, srv.sawAny(tc.wantAuth), "commands: %v", srv.commands())
			assert.True(t, srv.received().Delivered)
		})
	}
}

func TestSend_StartTLSRequired(t *testing.T) {
	srv := startServer(t, serverOpts{StartTLS: false, AuthMechs: "PLAIN LOGIN", User: user, Pass: pass})
	// Even allow_insecure_auth must not make starttls mode continue in clear.
	cfg := withAuth(baseCfg(srv.port(), "starttls"), "auto", true)

	err := send(t, cfg)
	requireClass(t, err, upstream.ClassTLS)
	assert.False(t, srv.sawAny("AUTH", "MAIL", "RCPT", "DATA"), "commands: %v", srv.commands())
	assert.False(t, srv.leaked(user, pass))
	assert.False(t, srv.received().Delivered)
}

func TestSend_StartTLSRefusedByServer(t *testing.T) {
	p := newPKI(t)
	srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN", User: user, Pass: pass,
		Fail: map[string]string{"STARTTLS": "454 4.7.0 TLS not available"}})
	cfg := withAuth(baseCfg(srv.port(), "starttls"), "auto", false)
	cfg.TLSOptions.CAFile = p.caFile

	err := send(t, cfg)
	requireClass(t, err, upstream.ClassTLS)
	assert.False(t, srv.leaked(user, pass))
	assert.False(t, srv.sawAny("MAIL"))
}

func TestSend_PlaintextAuthRefused(t *testing.T) {
	for _, mech := range []string{"plain", "login", "auto"} {
		t.Run(mech, func(t *testing.T) {
			srv := startServer(t, serverOpts{AuthMechs: "PLAIN LOGIN", User: user, Pass: pass})
			cfg := withAuth(baseCfg(srv.port(), "none"), mech, false)

			err := send(t, cfg)
			requireClass(t, err, upstream.ClassAuth)
			assert.False(t, srv.leaked(user, pass), "credentials reached the server: %v", srv.commands())
			assert.False(t, srv.sawAny("MAIL"))
			assert.False(t, srv.received().Delivered)
		})
	}
}

func TestSend_PlaintextAuthAllowedExplicitly(t *testing.T) {
	for _, tc := range []struct{ advertise, mech, want string }{
		{"PLAIN LOGIN", "plain", "AUTH PLAIN"},
		{"PLAIN LOGIN", "login", "AUTH LOGIN"},
		{"PLAIN LOGIN", "auto", "AUTH PLAIN"},
		{"LOGIN", "auto", "AUTH LOGIN"},
	} {
		t.Run(tc.mech+"/"+tc.advertise, func(t *testing.T) {
			srv := startServer(t, serverOpts{AuthMechs: tc.advertise, User: user, Pass: pass})
			cfg := withAuth(baseCfg(srv.port(), "none"), tc.mech, true)

			require.NoError(t, send(t, cfg))
			assert.True(t, srv.sawAny(tc.want), "commands: %v", srv.commands())
			assert.True(t, srv.received().Delivered)
		})
	}
}

func TestSend_WrongPassword(t *testing.T) {
	for _, mech := range []string{"plain", "login"} {
		t.Run(mech, func(t *testing.T) {
			p := newPKI(t)
			srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN LOGIN", User: user, Pass: "other"})
			cfg := withAuth(baseCfg(srv.port(), "starttls"), mech, false)
			cfg.TLSOptions.CAFile = p.caFile

			err := send(t, cfg)
			ue := requireClass(t, err, upstream.ClassAuth)
			assert.Equal(t, 535, ue.Code)
			assert.Contains(t, ue.Message, "Authentication credentials invalid")
			assert.NotContains(t, err.Error(), user)
			assert.False(t, srv.sawAny("MAIL"))
		})
	}
}

func TestSend_ServerCertificate(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t) // CA the client has not been told about

	t.Run("untrusted cert rejected (starttls)", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN", User: user, Pass: pass})
		cfg := withAuth(baseCfg(srv.port(), "starttls"), "auto", false)
		err := send(t, cfg) // system roots do not know the test CA
		requireClass(t, err, upstream.ClassTLS)
		assert.False(t, srv.leaked(user, pass))
		assert.False(t, srv.sawAny("MAIL"))
	})
	t.Run("untrusted cert rejected (implicit)", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, Implicit: true, User: user, Pass: pass})
		err := send(t, baseCfg(srv.port(), "tls"))
		requireClass(t, err, upstream.ClassTLS)
		assert.False(t, srv.received().Delivered)
	})
	t.Run("wrong custom CA rejected", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, Implicit: true})
		cfg := baseCfg(srv.port(), "tls")
		cfg.TLSOptions.CAFile = other.caFile
		requireClass(t, send(t, cfg), upstream.ClassTLS)
	})
	t.Run("insecure_skip_verify accepts", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN", User: user, Pass: pass})
		cfg := withAuth(baseCfg(srv.port(), "starttls"), "auto", false)
		cfg.TLSOptions.InsecureSkipVerify = true
		require.NoError(t, send(t, cfg))
		assert.True(t, srv.received().Delivered)
	})
	t.Run("custom CA accepts", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, Implicit: true})
		cfg := baseCfg(srv.port(), "tls")
		cfg.TLSOptions.CAFile = p.caFile
		require.NoError(t, send(t, cfg))
		assert.True(t, srv.received().Delivered)
	})
	t.Run("hostname mismatch rejected", func(t *testing.T) {
		srv := startServer(t, serverOpts{TLSConfig: p.serverTLS, Implicit: true})
		cfg := baseCfg(srv.port(), "tls")
		cfg.Host = "localhost" // cert only has the 127.0.0.1 SAN
		cfg.TLSOptions.CAFile = p.caFile
		requireClass(t, send(t, cfg), upstream.ClassTLS)
	})
}

func TestSend_MutualTLS(t *testing.T) {
	ca := newTestCA(t, "mtls-ca")
	serverCert, _, _ := ca.issue(t, "fake.test")
	_, clientCertPEM, clientKeyPEM := ca.issue(t, "relay-client")
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
		MinVersion:   tls.VersionTLS12,
	}
	caFile := writeFile(t, "ca.pem", ca.pem)

	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode+" with client cert", func(t *testing.T) {
			srv := startServer(t, serverOpts{TLSConfig: serverTLS, Implicit: mode == "tls", StartTLS: mode == "starttls"})
			cfg := baseCfg(srv.port(), mode)
			cfg.TLSOptions = config.UpstreamTLSOptions{
				CAFile:         caFile,
				ClientCertFile: writeFile(t, "c.pem", clientCertPEM),
				ClientKeyFile:  writeFile(t, "k.pem", clientKeyPEM),
			}
			require.NoError(t, send(t, cfg))
			certs := srv.clientCerts()
			require.NotEmpty(t, certs)
			assert.Equal(t, "relay-client", certs[0].Subject.CommonName)
			assert.True(t, srv.received().Delivered)
		})
		t.Run(mode+" without client cert fails", func(t *testing.T) {
			srv := startServer(t, serverOpts{TLSConfig: serverTLS, Implicit: mode == "tls", StartTLS: mode == "starttls"})
			cfg := baseCfg(srv.port(), mode)
			cfg.TLSOptions.CAFile = caFile
			requireClass(t, send(t, cfg), upstream.ClassTLS)
			assert.False(t, srv.received().Delivered)
		})
	}
}

func TestNew_Validation(t *testing.T) {
	good := newTestCA(t, "x")
	tests := []struct {
		name string
		mut  func(*config.UpstreamConfig)
	}{
		{"unknown tls mode", func(c *config.UpstreamConfig) { c.TLS = "bogus" }},
		{"missing ca file", func(c *config.UpstreamConfig) { c.TLSOptions.CAFile = "/nonexistent/ca.pem" }},
		{"ca file without certs", func(c *config.UpstreamConfig) { c.TLSOptions.CAFile = writeFile(t, "junk.pem", []byte("junk")) }},
		{"cert without key", func(c *config.UpstreamConfig) { c.TLSOptions.ClientCertFile = writeFile(t, "c.pem", good.pem) }},
		{"unreadable client pair", func(c *config.UpstreamConfig) {
			c.TLSOptions.ClientCertFile = "/nonexistent/c.pem"
			c.TLSOptions.ClientKeyFile = "/nonexistent/k.pem"
		}},
		{"unknown mechanism", func(c *config.UpstreamConfig) { c.Auth = &config.AuthConfig{Mechanism: "cram-md5"} }},
		{"missing password file", func(c *config.UpstreamConfig) {
			c.Auth = &config.AuthConfig{Mechanism: "auto", PasswordFile: "/nonexistent/pw"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseCfg(25, "starttls")
			tc.mut(&cfg)
			_, err := upstream.New(cfg, ehlo)
			assert.Error(t, err)
		})
	}
}

func TestSend_PasswordFile(t *testing.T) {
	srv := startServer(t, serverOpts{AuthMechs: "PLAIN", User: user, Pass: pass})
	cfg := baseCfg(srv.port(), "none")
	cfg.Auth = &config.AuthConfig{
		Mechanism: "auto", Username: user, AllowInsecureAuth: true,
		PasswordFile: writeFile(t, "pw", []byte(pass+"\n")),
	}
	require.NoError(t, send(t, cfg))
}

func TestSend_ConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	requireClass(t, send(t, baseCfg(port, "none")), upstream.ClassConnect)
	requireClass(t, send(t, baseCfg(port, "tls")), upstream.ClassConnect)
}

func TestSend_Name(t *testing.T) {
	s, err := upstream.New(baseCfg(25, "none"), ehlo)
	require.NoError(t, err)
	assert.Equal(t, "fake", s.Name())
}

func TestSend_Timeouts(t *testing.T) {
	p := newPKI(t)
	tests := []struct {
		name string
		hang string
		mode string
		opts func(*serverOpts)
		cfg  func(*config.UpstreamConfig)
	}{
		{name: "hang at greeting", hang: "GREETING", mode: "none"},
		{name: "hang at EHLO", hang: "EHLO", mode: "none"},
		{name: "hang at STARTTLS", hang: "STARTTLS", mode: "starttls", opts: func(o *serverOpts) { o.StartTLS = true }},
		{name: "hang at AUTH", hang: "AUTH", mode: "none", opts: func(o *serverOpts) { o.AuthMechs = "PLAIN" },
			cfg: func(c *config.UpstreamConfig) { *c = withAuth(*c, "plain", true) }},
		{name: "hang at MAIL", hang: "MAIL", mode: "none"},
		{name: "hang at RCPT", hang: "RCPT", mode: "none"},
		{name: "hang at DATA", hang: "DATA", mode: "none"},
		{name: "hang waiting for final DATA reply", hang: "AFTERDATA", mode: "none"},
		{name: "hang during implicit TLS handshake", hang: "GREETING", mode: "tls", opts: func(o *serverOpts) { o.Implicit = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := serverOpts{TLSConfig: p.serverTLS, Hang: tc.hang, User: user, Pass: pass}
			if tc.opts != nil {
				tc.opts(&o)
			}
			srv := startServer(t, o)
			cfg := baseCfg(srv.port(), tc.mode)
			cfg.TLSOptions.CAFile = p.caFile
			cfg.Timeouts = config.UpstreamTimeouts{Connect: 200 * time.Millisecond, Command: 200 * time.Millisecond, Data: 200 * time.Millisecond}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}

			start := time.Now()
			err := send(t, cfg)
			elapsed := time.Since(start)
			requireClass(t, err, upstream.ClassTimeout)
			assert.Less(t, elapsed, 2*time.Second, "timeout must fire near the configured value")
			assert.GreaterOrEqual(t, elapsed, 150*time.Millisecond)
		})
	}
}

func TestSend_DataTimeoutIsSeparate(t *testing.T) {
	// A short command timeout must not cut a slow DATA phase short: only the
	// data timeout applies there. The fake server answers after 300ms.
	srv := startServer(t, serverOpts{DataDelay: 300 * time.Millisecond})
	cfg := baseCfg(srv.port(), "none")
	cfg.Timeouts = config.UpstreamTimeouts{Connect: time.Second, Command: 150 * time.Millisecond, Data: 2 * time.Second}
	require.NoError(t, send(t, cfg))
	assert.True(t, srv.received().Delivered)
}

func TestSend_SMTPErrorClassification(t *testing.T) {
	tests := []struct {
		stage string
		reply string
		class upstream.Class
		code  int
		msg   string
	}{
		{"MAIL", "451 4.3.0 try later", upstream.ClassSMTP4xx, 451, "4.3.0 try later"},
		{"MAIL", "550 5.7.1 sender rejected", upstream.ClassSMTP5xx, 550, "5.7.1 sender rejected"},
		{"RCPT", "452 4.2.2 mailbox full", upstream.ClassSMTP4xx, 452, "4.2.2 mailbox full"},
		{"RCPT", "550 5.1.1 no such user", upstream.ClassSMTP5xx, 550, "5.1.1 no such user"},
		{"DATA", "451 4.3.0 cannot accept data", upstream.ClassSMTP4xx, 451, "4.3.0 cannot accept data"},
		{"DATA", "554 5.3.0 transaction failed", upstream.ClassSMTP5xx, 554, "5.3.0 transaction failed"},
		{"AFTERDATA", "421 4.4.2 timeout waiting", upstream.ClassSMTP4xx, 421, "4.4.2 timeout waiting"},
		{"AFTERDATA", "554 5.7.0 rejected as spam", upstream.ClassSMTP5xx, 554, "5.7.0 rejected as spam"},
	}
	for _, tc := range tests {
		t.Run(tc.stage+"/"+tc.reply, func(t *testing.T) {
			srv := startServer(t, serverOpts{Fail: map[string]string{tc.stage: tc.reply}})
			err := send(t, baseCfg(srv.port(), "none"))
			ue := requireClass(t, err, tc.class)
			assert.Equal(t, tc.code, ue.Code)
			assert.Equal(t, tc.msg, ue.Message)
			var te interface{ Error() string }
			assert.ErrorAs(t, err, &te)
			assert.False(t, srv.received().Delivered)
		})
	}
}

func TestSend_AbruptClose(t *testing.T) {
	for _, stage := range []string{"GREETING", "EHLO", "MAIL", "RCPT", "DATA", "AFTERDATA"} {
		t.Run(stage, func(t *testing.T) {
			srv := startServer(t, serverOpts{CloseAt: stage})
			err := send(t, baseCfg(srv.port(), "none"))
			require.Error(t, err)
			var ue *upstream.Error
			require.ErrorAs(t, err, &ue)
			assert.Contains(t, []upstream.Class{upstream.ClassOther, upstream.ClassConnect}, ue.Class)
			assert.Zero(t, ue.Code)
		})
	}
}

func TestSend_ContextCancel(t *testing.T) {
	srv := startServer(t, serverOpts{Hang: "RCPT"})
	cfg := baseCfg(srv.port(), "none")
	cfg.Timeouts = config.UpstreamTimeouts{Connect: 5 * time.Second, Command: 5 * time.Second, Data: 5 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	err := sendCtx(t, ctx, cfg)
	requireClass(t, err, upstream.ClassOther)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestSend_ContextDeadline(t *testing.T) {
	srv := startServer(t, serverOpts{Hang: "RCPT"})
	cfg := baseCfg(srv.port(), "none")
	cfg.Timeouts = config.UpstreamTimeouts{Connect: 5 * time.Second, Command: 5 * time.Second, Data: 5 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := sendCtx(t, ctx, cfg)
	requireClass(t, err, upstream.ClassTimeout)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestSend_ContextAlreadyCancelled(t *testing.T) {
	srv := startServer(t, serverOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireClass(t, sendCtx(t, ctx, baseCfg(srv.port(), "none")), upstream.ClassOther)
	assert.Zero(t, srv.connections())
}

func TestSend_RejectsCRLFInAddresses(t *testing.T) {
	srv := startServer(t, serverOpts{})
	s, err := upstream.New(baseCfg(srv.port(), "none"), ehlo)
	require.NoError(t, err)

	tests := []struct {
		name string
		from string
		to   []string
	}{
		{"CR in from", "a@example.com\rRSET", []string{"b@example.com"}},
		{"LF in from", "a@example.com\nRSET", []string{"b@example.com"}},
		{"CRLF in rcpt", "a@example.com", []string{"b@example.com>\r\nMAIL FROM:<x@y"}},
		{"LF in second rcpt", "a@example.com", []string{"b@example.com", "c@example.com\n"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Send(context.Background(), tc.from, tc.to, testMsg)
			requireClass(t, err, upstream.ClassOther)
		})
	}
	assert.Zero(t, srv.connections(), "must not connect at all")
}

func TestSend_MessageUnchanged(t *testing.T) {
	long := strings.Repeat("0123456789abcdef", 400) // 6400 bytes on one line
	tests := []struct {
		name string
		data string
	}{
		{"headers and plain body", "From: a@example.com\r\nTo: b@example.com\r\nSubject: hello\r\nMessage-ID: <abc@example.com>\r\nReceived: from x by y; Thu, 22 Oct 2026 10:00:00 +0000\r\n\r\nbody\r\n"},
		{"line with a single dot", "Subject: dots\r\n\r\nbefore\r\n.\r\nafter\r\n..two\r\n.leading\r\n"},
		{"non-ASCII UTF-8", "Subject: =?UTF-8?B?4pyT?=\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nxin chào thế giới — ✓ 日本語\r\n"},
		{"long line", "Subject: long\r\n\r\n" + long + "\r\nend\r\n"},
		{"header only", "Subject: only\r\n\r\n"},
		{"folded header", "Subject: a\r\n very long folded\r\n\tsubject\r\n\r\nx\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, serverOpts{})
			s, err := upstream.New(baseCfg(srv.port(), "none"), ehlo)
			require.NoError(t, err)
			from := "sender+tag@example.com"
			to := []string{"r1@example.com", "r2@example.org", "r3@example.net"}

			require.NoError(t, s.Send(context.Background(), from, to, []byte(tc.data)))

			got := srv.received()
			assert.Equal(t, "<"+from+">", got.MailFrom)
			assert.Equal(t, []string{"<r1@example.com>", "<r2@example.org>", "<r3@example.net>"}, got.Rcpts)
			assert.Equal(t, tc.data, string(got.Data), "DATA must arrive byte-identical, no headers added")
		})
	}
}

func TestSend_BareLFNormalisedToCRLF(t *testing.T) {
	srv := startServer(t, serverOpts{})
	s, err := upstream.New(baseCfg(srv.port(), "none"), ehlo)
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), "a@example.com", []string{"b@example.com"}, []byte("Subject: x\n\nline1\nline2\n")))
	assert.Equal(t, "Subject: x\r\n\r\nline1\r\nline2\r\n", string(srv.received().Data))
}

func TestSend_OneConnectionPerSendAndConcurrent(t *testing.T) {
	srv := startServer(t, serverOpts{})
	s, err := upstream.New(baseCfg(srv.port(), "none"), ehlo)
	require.NoError(t, err)

	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { errs <- s.Send(context.Background(), "a@example.com", []string{"b@example.com"}, testMsg) }()
	}
	for i := 0; i < 4; i++ {
		require.NoError(t, <-errs)
	}
	assert.Equal(t, 4, srv.connections())
}

func TestSend_ErrorsNeverContainSecrets(t *testing.T) {
	p := newPKI(t)
	var all []error

	srv1 := startServer(t, serverOpts{AuthMechs: "PLAIN LOGIN", User: user, Pass: pass})
	all = append(all, send(t, withAuth(baseCfg(srv1.port(), "none"), "auto", false)))

	srv2 := startServer(t, serverOpts{TLSConfig: p.serverTLS, StartTLS: true, AuthMechs: "PLAIN", User: user, Pass: "wrong"})
	cfg := withAuth(baseCfg(srv2.port(), "starttls"), "plain", false)
	cfg.TLSOptions.CAFile = p.caFile
	all = append(all, send(t, cfg))

	srv3 := startServer(t, serverOpts{AuthMechs: "PLAIN", User: user, Pass: "wrong"})
	all = append(all, send(t, withAuth(baseCfg(srv3.port(), "none"), "login", true)))

	for _, err := range all {
		require.Error(t, err)
		assert.NotContains(t, err.Error(), pass)
		var ue *upstream.Error
		if errors.As(err, &ue) {
			assert.NotContains(t, ue.Message, pass)
		}
	}
}
