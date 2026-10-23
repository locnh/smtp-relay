package server

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/locnh/smtp-relay/internal/maillog"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/upstream"
)

type fakeDeliverer struct {
	mu   sync.Mutex
	msgs []*relay.Message
	fn   func(ctx context.Context, m *relay.Message) relay.Result
}

func (d *fakeDeliverer) Deliver(ctx context.Context, m *relay.Message) relay.Result {
	d.mu.Lock()
	d.msgs = append(d.msgs, m)
	fn := d.fn
	d.mu.Unlock()
	if fn != nil {
		return fn(ctx, m)
	}
	return relay.Result{Upstream: "up1", Attempts: []relay.Attempt{{Upstream: "up1"}}}
}

func (d *fakeDeliverer) messages() []*relay.Message {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*relay.Message(nil), d.msgs...)
}

type doneRec struct {
	s   maillog.Summary
	res relay.Result
}

type fakeEvents struct {
	mu         sync.Mutex
	rejected   []string
	accepted   map[string]int
	closed     map[string]int
	connReject [][2]string
	received   []int
	done       []doneRec
	live, min  int
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{accepted: map[string]int{}, closed: map[string]int{}}
}

func (e *fakeEvents) MessageRejected(r string) {
	e.mu.Lock()
	e.rejected = append(e.rejected, r)
	e.mu.Unlock()
}
func (e *fakeEvents) ConnAccepted(l string) {
	e.mu.Lock()
	e.accepted[l]++
	e.live++
	e.mu.Unlock()
}
func (e *fakeEvents) ConnClosed(l string) {
	e.mu.Lock()
	e.closed[l]++
	e.live--
	if e.live < e.min {
		e.min = e.live
	}
	e.mu.Unlock()
}
func (e *fakeEvents) ConnRejected(l, r string) {
	e.mu.Lock()
	e.connReject = append(e.connReject, [2]string{l, r})
	e.mu.Unlock()
}
func (e *fakeEvents) MessageReceived(n int) {
	e.mu.Lock()
	e.received = append(e.received, n)
	e.mu.Unlock()
}
func (e *fakeEvents) MessageDone(s maillog.Summary, r relay.Result) {
	e.mu.Lock()
	e.done = append(e.done, doneRec{s, r})
	e.mu.Unlock()
}

func (e *fakeEvents) snapshot() (rejected []string, done []doneRec, connReject [][2]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.rejected...), append([]doneRec(nil), e.done...), append([][2]string(nil), e.connReject...)
}

func (e *fakeEvents) liveCount() (live, min int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.live, e.min
}

// testCert writes a self-signed ECDSA P-256 certificate and returns the file paths.
func testCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour).Truncate(time.Second),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"relay.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

type harness struct {
	srv *Server
	del *fakeDeliverer
	ev  *fakeEvents
}

type opt func(*Config)

func baseConfig(listen ...config.ListenConfig) Config {
	if len(listen) == 0 {
		listen = []config.ListenConfig{{Address: "127.0.0.1:0", TLS: "none"}}
	}
	return Config{
		Server: config.ServerConfig{
			Listen:   listen,
			Timeouts: config.ServerTimeouts{Read: 5 * time.Second, Write: 5 * time.Second, Data: 5 * time.Second, Shutdown: 5 * time.Second},
			Limits:   config.ServerLimits{MaxConnections: 100, MaxMessageSize: 1 << 20, MaxRecipients: 100},
		},
		Policy:   NewPolicy(config.AccessConfig{}),
		Log:      zerolog.Nop(),
		Hostname: "relay.test",
	}
}

func start(t *testing.T, c Config, opts ...opt) *harness {
	t.Helper()
	h := &harness{del: &fakeDeliverer{}, ev: newFakeEvents()}
	c.Deliverer = h.del
	c.Events = h.ev
	for _, o := range opts {
		o(&c)
	}
	srv, err := New(c)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	h.srv = srv
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return h
}

func (h *harness) addr(i int) string { return h.srv.Addrs()[i].String() }

// rawClient speaks SMTP lines directly so replies can be asserted exactly.
type rawClient struct {
	t    *testing.T
	conn net.Conn
	r    *textproto.Reader
}

func dialRaw(t *testing.T, addr string) *rawClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	return newRaw(t, c)
}

func newRaw(t *testing.T, c net.Conn) *rawClient {
	rc := &rawClient{t: t, conn: c, r: textproto.NewReader(bufio.NewReader(c))}
	t.Cleanup(func() { _ = c.Close() })
	return rc
}

// reply reads one (possibly multi-line) reply and returns the final line and all lines.
func (c *rawClient) reply() (string, []string) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var lines []string
	for {
		l, err := c.r.ReadLine()
		require.NoError(c.t, err)
		lines = append(lines, l)
		if len(l) < 4 || l[3] != '-' {
			return l, lines
		}
	}
}

func (c *rawClient) cmd(line string) (string, []string) {
	c.t.Helper()
	_, err := fmt.Fprintf(c.conn, "%s\r\n", line)
	require.NoError(c.t, err)
	return c.reply()
}

func (c *rawClient) expect(line, prefix string) []string {
	c.t.Helper()
	last, all := c.cmd(line)
	require.True(c.t, strings.HasPrefix(last, prefix), "%q: want prefix %q, got %q", line, prefix, last)
	return all
}

func (c *rawClient) greet() {
	c.t.Helper()
	l, _ := c.reply()
	require.True(c.t, strings.HasPrefix(l, "220 "), l)
	c.expect("EHLO client.test", "250 ")
}

func (c *rawClient) sendMail(from string, rcpts []string, body string) string {
	c.t.Helper()
	c.expect("MAIL FROM:<"+from+">", "250 ")
	for _, r := range rcpts {
		c.expect("RCPT TO:<"+r+">", "250 ")
	}
	c.expect("DATA", "354 ")
	_, err := c.conn.Write([]byte(body + "\r\n.\r\n"))
	require.NoError(c.t, err)
	l, _ := c.reply()
	return l
}

func (c *rawClient) expectEOF() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.r.ReadLine()
	require.Error(c.t, err)
}

const testBody = "From: a@example.com\r\nSubject: Hello there\r\n\r\nline one\r\n..dotted\r\nlast"

func TestHappyPath(t *testing.T) {
	h := start(t, baseConfig())
	c := dialRaw(t, h.addr(0))
	c.greet()

	last := c.sendMail("alerts@example.com", []string{"a@x.test", "b@x.test"}, testBody)
	assert.Equal(t, "250 2.0.0 OK: queued", last)

	msgs := h.del.messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "alerts@example.com", msgs[0].From)
	assert.Equal(t, []string{"a@x.test", "b@x.test"}, msgs[0].To)
	assert.Equal(t, "127.0.0.1", msgs[0].Peer)
	assert.NotEmpty(t, msgs[0].ID)
	// The client dot-stuffed "..dotted"; the server delivers the unstuffed DATA payload.
	assert.Equal(t, "From: a@example.com\r\nSubject: Hello there\r\n\r\nline one\r\n.dotted\r\nlast\r\n", string(msgs[0].Data))

	_, done, _ := h.ev.snapshot()
	require.Len(t, done, 1)
	s := done[0].s
	assert.Equal(t, msgs[0].ID, s.ID)
	assert.Equal(t, "127.0.0.1", s.Peer)
	assert.Equal(t, "alerts@example.com", s.From)
	assert.Equal(t, []string{"a@x.test", "b@x.test"}, s.To)
	assert.Equal(t, "Hello there", s.Subject)
	assert.Equal(t, maillog.StatusDelivered, s.Status)
	assert.Equal(t, "up1", s.Upstream)
	assert.Equal(t, 1, s.Attempts)
	assert.Equal(t, len(msgs[0].Data), s.Size)
	assert.NoError(t, s.Err)
	h.ev.mu.Lock()
	assert.Equal(t, []int{len(msgs[0].Data)}, h.ev.received)
	h.ev.mu.Unlock()

	// The session is reusable for a second transaction.
	assert.Equal(t, "250 2.0.0 OK: queued", c.sendMail("alerts@example.com", []string{"c@x.test"}, "Subject: two\r\n\r\nb"))
	_, done, _ = h.ev.snapshot()
	assert.Len(t, done, 2)
}

func TestNewIDInjectable(t *testing.T) {
	h := start(t, baseConfig(), func(c *Config) { c.NewID = func() string { return "fixed-id" } })
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: x\r\n\r\nb")
	assert.Equal(t, "fixed-id", h.del.messages()[0].ID)
}

func TestNoAuthAdvertisedAndRefused(t *testing.T) {
	h := start(t, baseConfig())
	c := dialRaw(t, h.addr(0))
	l, _ := c.reply()
	require.Contains(t, l, "220 relay.test")
	lines := c.expect("EHLO client.test", "250 ")
	for _, l := range lines {
		assert.NotContains(t, strings.ToUpper(l), "AUTH")
	}
	for _, cmd := range []string{"AUTH PLAIN AGEAYg==", "AUTH LOGIN"} {
		last, _ := c.cmd(cmd)
		assert.True(t, strings.HasPrefix(last, "5"), "%s -> %s", cmd, last)
	}
	// Unauthenticated mail still goes through.
	assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: x\r\n\r\nb"), "250 "))
}

func TestWelcomeMessageInBanner(t *testing.T) {
	c0 := baseConfig()
	c0.Server.WelcomeMessage = "Hi there"
	h := start(t, c0)
	c := dialRaw(t, h.addr(0))
	l, _ := c.reply()
	assert.Contains(t, l, "Hi there")
}

func TestSenderRejection(t *testing.T) {
	tests := []struct {
		name, mailFrom, reason string
	}{
		{"denied sender", "evil@other.test", "sender_denied"},
		{"null sender", "", "null_sender"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c0 := baseConfig()
			c0.Policy = NewPolicy(config.AccessConfig{AllowedSenders: []string{"ok@example.com"}})
			h := start(t, c0)
			c := dialRaw(t, h.addr(0))
			c.greet()
			c.expect("MAIL FROM:<"+tc.mailFrom+">", "550 5.7.1 Sender address not allowed")
			rejected, done, _ := h.ev.snapshot()
			assert.Equal(t, []string{tc.reason}, rejected)
			assert.Empty(t, done)
			// An allowed sender is still accepted on the same connection.
			c.expect("MAIL FROM:<ok@example.com>", "250 ")
		})
	}
}

func TestNullSenderRejectedWhenOpen(t *testing.T) {
	h := start(t, baseConfig())
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.expect("MAIL FROM:<>", "550 5.7.1 ")
	rejected, _, _ := h.ev.snapshot()
	assert.Equal(t, []string{"null_sender"}, rejected)
}

func TestNetworkDenied(t *testing.T) {
	_, n, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	c0 := baseConfig()
	c0.Policy = NewPolicy(config.AccessConfig{Networks: []*net.IPNet{n}})
	h := start(t, c0)

	c := dialRaw(t, h.addr(0))
	l, _ := c.reply()
	assert.Equal(t, "554 5.7.1 Access denied", l)
	c.expectEOF()

	require.Eventually(t, func() bool { _, _, cr := h.ev.snapshot(); return len(cr) == 1 }, 2*time.Second, 5*time.Millisecond)
	_, _, cr := h.ev.snapshot()
	assert.Equal(t, [2]string{"127.0.0.1:0", "denied_network"}, cr[0])
	live, _ := h.ev.liveCount()
	assert.Zero(t, live)
	h.ev.mu.Lock()
	assert.Empty(t, h.ev.accepted)
	h.ev.mu.Unlock()
}

func TestMaxConnections(t *testing.T) {
	c0 := baseConfig()
	c0.Server.Limits.MaxConnections = 1
	h := start(t, c0)

	first := dialRaw(t, h.addr(0))
	first.greet()

	second := dialRaw(t, h.addr(0))
	l, _ := second.reply()
	assert.Equal(t, "421 4.7.0 Too many connections", l)
	second.expectEOF()
	_, _, cr := h.ev.snapshot()
	require.Len(t, cr, 1)
	assert.Equal(t, "rejected_limit", cr[0][1])

	first.expect("QUIT", "221 ")
	first.expectEOF()
	require.Eventually(t, func() bool {
		c := dialRaw(t, h.addr(0))
		l, _ := c.reply()
		return strings.HasPrefix(l, "220 ")
	}, 3*time.Second, 20*time.Millisecond)
}

func TestMaxConnectionsSharedAcrossListeners(t *testing.T) {
	c0 := baseConfig(config.ListenConfig{Address: "127.0.0.1:0", TLS: "none"}, config.ListenConfig{Address: "127.0.0.1:0", TLS: "none"})
	c0.Server.Limits.MaxConnections = 1
	h := start(t, c0)
	require.Len(t, h.srv.Addrs(), 2)

	first := dialRaw(t, h.addr(0))
	first.greet()
	second := dialRaw(t, h.addr(1))
	l, _ := second.reply()
	assert.Equal(t, "421 4.7.0 Too many connections", l)
}

func TestMaxRecipients(t *testing.T) {
	c0 := baseConfig()
	c0.Server.Limits.MaxRecipients = 2
	h := start(t, c0)
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.expect("MAIL FROM:<a@example.com>", "250 ")
	c.expect("RCPT TO:<1@x.test>", "250 ")
	c.expect("RCPT TO:<2@x.test>", "250 ")
	c.expect("RCPT TO:<3@x.test>", "452 4.5.3 ")
	rejected, _, _ := h.ev.snapshot()
	assert.Equal(t, []string{"too_many_recipients"}, rejected)

	c.expect("DATA", "354 ")
	_, err := c.conn.Write([]byte("Subject: s\r\n\r\nb\r\n.\r\n"))
	require.NoError(t, err)
	l, _ := c.reply()
	assert.True(t, strings.HasPrefix(l, "250 "))
	assert.Equal(t, []string{"1@x.test", "2@x.test"}, h.del.messages()[0].To)

	// The recipient count starts over for the next transaction.
	assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"4@x.test", "5@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
}

func TestMessageTooLarge(t *testing.T) {
	c0 := baseConfig()
	c0.Server.Limits.MaxMessageSize = 1000
	h := start(t, c0)
	c := dialRaw(t, h.addr(0))
	c.greet()

	big := "Subject: big\r\n\r\n" + strings.Repeat("0123456789abcdef\r\n", 200)
	l := c.sendMail("a@example.com", []string{"b@x.test"}, big)
	assert.True(t, strings.HasPrefix(l, "552 5.3.4 "), l)

	rejected, done, _ := h.ev.snapshot()
	assert.Equal(t, []string{"size_exceeded"}, rejected)
	assert.Empty(t, done)
	assert.Empty(t, h.del.messages())
	h.ev.mu.Lock()
	assert.Empty(t, h.ev.received)
	h.ev.mu.Unlock()

	// The connection survives and accepts a small mail.
	assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
}

func TestSlowDripDataCutByTotalDeadline(t *testing.T) {
	c0 := baseConfig()
	c0.Server.Timeouts.Data = 500 * time.Millisecond
	c0.Server.Timeouts.Read = 5 * time.Second
	h := start(t, c0)
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.expect("MAIL FROM:<a@example.com>", "250 ")
	c.expect("RCPT TO:<b@x.test>", "250 ")
	c.expect("DATA", "354 ")

	start := time.Now()
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				if _, err := c.conn.Write([]byte("x")); err != nil {
					return
				}
			}
		}
	}()
	defer close(stop)

	l, _ := c.reply()
	elapsed := time.Since(start)
	assert.True(t, strings.HasPrefix(l, "421 4.4.2 "), l)
	assert.GreaterOrEqual(t, elapsed, 450*time.Millisecond)
	assert.Less(t, elapsed, 1500*time.Millisecond, "per-line read timeout must not extend the DATA budget")
	c.expectEOF()

	_, done, _ := h.ev.snapshot()
	assert.Empty(t, done)
	assert.Empty(t, h.del.messages())
}

func TestFailedDelivery(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantLast string
	}{
		{"connection error", &upstream.Error{Class: upstream.ClassConnect, Message: "dial smtp.secret.test"}, "421 4.4.0 Forwarding failed"},
		{"upstream 5xx", &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: "no such user"}, "550 5.0.0 no such user"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := start(t, baseConfig())
			h.del.fn = func(context.Context, *relay.Message) relay.Result {
				return relay.Result{Attempts: []relay.Attempt{{Upstream: "u1", Err: tc.err}, {Upstream: "u2", Err: tc.err}}, Err: tc.err}
			}
			c := dialRaw(t, h.addr(0))
			c.greet()
			l := c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb")
			assert.Equal(t, tc.wantLast, l)
			assert.NotContains(t, l, "secret")

			_, done, _ := h.ev.snapshot()
			require.Len(t, done, 1)
			assert.Equal(t, maillog.StatusFailed, done[0].s.Status)
			assert.Equal(t, 2, done[0].s.Attempts)
			assert.Equal(t, tc.err, done[0].s.Err)
			assert.Equal(t, tc.err, done[0].res.Err)
		})
	}
}

func TestDataBeforeEnvelopeIsRefused(t *testing.T) {
	h := start(t, baseConfig())
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.expect("DATA", "502 ")
	c.expect("RCPT TO:<a@x.test>", "502 ")
	c.expect("MAIL FROM:<a@example.com>", "250 ")
	c.expect("DATA", "502 ")
	c.expect("RSET", "250 ")
	c.expect("RCPT TO:<a@x.test>", "502 ")
	assert.Empty(t, h.del.messages())
}

func TestNestedMailIsRefused(t *testing.T) {
	h := start(t, baseConfig())
	c := dialRaw(t, h.addr(0))
	c.greet()
	c.expect("MAIL FROM:<a@example.com>", "250 ")
	c.expect("MAIL FROM:<b@example.com>", "503 5.5.1 ")
	c.expect("RSET", "250 ")
	assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
}

func TestStartTLSAndForceTLS(t *testing.T) {
	certFile, keyFile := testCert(t)
	c0 := baseConfig(
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "starttls", ForceTLS: true},
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "starttls"},
	)
	c0.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, Profile: "default"}
	h := start(t, c0)

	t.Run("force_tls blocks MAIL until upgraded", func(t *testing.T) {
		c := dialRaw(t, h.addr(0))
		l, _ := c.reply()
		require.True(t, strings.HasPrefix(l, "220 "))
		ehlo := c.expect("EHLO client.test", "250 ")
		assert.Contains(t, strings.Join(ehlo, "\n"), "STARTTLS")
		c.expect("MAIL FROM:<a@example.com>", "530 5.7.0 Must issue a STARTTLS command first")

		c.expect("STARTTLS", "220 ")
		tc := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
		require.NoError(t, tc.Handshake())
		tcc := newRaw(t, tc)
		ehlo = tcc.expect("EHLO client.test", "250 ")
		assert.NotContains(t, strings.Join(ehlo, "\n"), "STARTTLS")
		assert.True(t, strings.HasPrefix(tcc.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
		assert.Len(t, h.del.messages(), 1)
	})

	t.Run("without force_tls plain mail is accepted", func(t *testing.T) {
		c := dialRaw(t, h.addr(1))
		c.greet()
		assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
	})

	t.Run("cert expiry is exposed", func(t *testing.T) {
		na, ok := h.srv.CertNotAfter()
		require.True(t, ok)
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), na, time.Minute)
	})
}

func TestImplicitTLSListener(t *testing.T) {
	certFile, keyFile := testCert(t)
	c0 := baseConfig(config.ListenConfig{Address: "127.0.0.1:0", TLS: "tls"})
	c0.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, Profile: "default"}
	h := start(t, c0)

	conn, err := tls.Dial("tcp", h.addr(0), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	c := newRaw(t, conn)
	c.greet()
	assert.True(t, strings.HasPrefix(c.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb"), "250 "))
	assert.Len(t, h.del.messages(), 1)
}

func TestImplicitTLSGateRunsBeforeHandshake(t *testing.T) {
	certFile, keyFile := testCert(t)
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	c0 := baseConfig(config.ListenConfig{Address: "127.0.0.1:0", TLS: "tls"})
	c0.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile}
	c0.Policy = NewPolicy(config.AccessConfig{Networks: []*net.IPNet{n}})
	h := start(t, c0)

	// A plain-text read sees the 554 line because no handshake was attempted.
	c := dialRaw(t, h.addr(0))
	l, _ := c.reply()
	assert.Equal(t, "554 5.7.1 Access denied", l)
}

func TestTLSProfiles(t *testing.T) {
	certFile, keyFile := testCert(t)
	serve := func(t *testing.T, profile string) string {
		c0 := baseConfig(config.ListenConfig{Address: "127.0.0.1:0", TLS: "tls"})
		c0.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, Profile: profile}
		return start(t, c0).addr(0)
	}
	handshake := func(addr string, cfg *tls.Config) (*tls.ConnectionState, error) {
		cfg.InsecureSkipVerify = true
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		st := conn.ConnectionState()
		return &st, nil
	}
	cbcOnly := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}
	gcm := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	t.Run("modern", func(t *testing.T) {
		addr := serve(t, "modern")
		_, err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		assert.Error(t, err, "TLS 1.2 client must be refused")
		st, err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS13})
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS13), st.Version)
	})
	t.Run("intermediate", func(t *testing.T) {
		addr := serve(t, "intermediate")
		_, err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: cbcOnly})
		assert.Error(t, err, "CBC-only TLS 1.2 client must be refused")
		_, err = handshake(addr, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, CipherSuites: cbcOnly})
		assert.Error(t, err, "TLS < 1.2 must be refused")
		st, err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: gcm})
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS12), st.Version)
	})
	t.Run("default", func(t *testing.T) {
		addr := serve(t, "default")
		st, err := handshake(addr, &tls.Config{})
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS13), st.Version)
	})
	t.Run("legacy", func(t *testing.T) {
		// Prove the Go client can speak TLS 1.0 at all before blaming the server.
		probe, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: mustLoad(t, certFile, keyFile), MinVersion: tls.VersionTLS10,
		})
		require.NoError(t, err)
		go func() {
			for {
				c, err := probe.Accept()
				if err != nil {
					return
				}
				go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
			}
		}()
		_, err = handshake(probe.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10})
		probe.Close()
		if err != nil {
			t.Skipf("Go toolchain refuses a TLS 1.0 client handshake here: %v", err)
		}

		addr := serve(t, "legacy")
		st, err := handshake(addr, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10})
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS10), st.Version)
		_, err = handshake(addr, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: cbcOnly})
		assert.NoError(t, err, "legacy keeps CBC suites")
	})
}

func mustLoad(t *testing.T, certFile, keyFile string) []tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	return []tls.Certificate{c}
}

func TestNewErrors(t *testing.T) {
	certFile, keyFile := testCert(t)
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"missing cert files", func(c *Config) {
			c.Server.Listen = []config.ListenConfig{{Address: "127.0.0.1:0", TLS: "starttls"}}
			c.Server.TLS = config.ServerTLSConfig{CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"}
		}},
		{"unknown profile", func(c *Config) {
			c.Server.Listen = []config.ListenConfig{{Address: "127.0.0.1:0", TLS: "tls"}}
			c.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile, Profile: "bogus"}
		}},
		{"unknown listener mode", func(c *Config) {
			c.Server.Listen = []config.ListenConfig{{Address: "127.0.0.1:0", TLS: "bogus"}}
		}},
		{"nil deliverer", func(c *Config) { c.Deliverer = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := baseConfig()
			c.Deliverer = &fakeDeliverer{}
			tc.mut(&c)
			_, err := New(c)
			assert.Error(t, err)
		})
	}

	t.Run("plain listeners need no certificate", func(t *testing.T) {
		c := baseConfig()
		c.Deliverer = &fakeDeliverer{}
		s, err := New(c)
		require.NoError(t, err)
		_, ok := s.CertNotAfter()
		assert.False(t, ok)
	})
}

func TestMultipleListeners(t *testing.T) {
	certFile, keyFile := testCert(t)
	c0 := baseConfig(
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "none"},
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "starttls"},
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "tls"},
	)
	c0.Server.TLS = config.ServerTLSConfig{CertFile: certFile, KeyFile: keyFile}
	h := start(t, c0)
	require.Len(t, h.srv.Addrs(), 3)

	plain := dialRaw(t, h.addr(0))
	plain.greet()
	assert.True(t, strings.HasPrefix(plain.sendMail("a@example.com", []string{"b@x.test"}, "Subject: 1\r\n\r\nb"), "250 "))

	st := dialRaw(t, h.addr(1))
	st.greet()
	st.expect("STARTTLS", "220 ")

	conn, err := tls.Dial("tcp", h.addr(2), &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	imp := newRaw(t, conn)
	imp.greet()
	assert.True(t, strings.HasPrefix(imp.sendMail("a@example.com", []string{"b@x.test"}, "Subject: 2\r\n\r\nb"), "250 "))

	h.ev.mu.Lock()
	// Listeners are labelled by their configured address, all "127.0.0.1:0" here.
	assert.Equal(t, 3, h.ev.accepted["127.0.0.1:0"])
	h.ev.mu.Unlock()
}

func TestStartFailureClosesBoundListeners(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer taken.Close()

	c := baseConfig(
		config.ListenConfig{Address: "127.0.0.1:0", TLS: "none"},
		config.ListenConfig{Address: taken.Addr().String(), TLS: "none"},
	)
	c.Deliverer = &fakeDeliverer{}
	s, err := New(c)
	require.NoError(t, err)
	require.Error(t, s.Start())

	first := s.Addrs()[0].String()
	_, err = net.DialTimeout("tcp", first, time.Second)
	assert.Error(t, err, "the first listener must have been closed again")
	assert.NoError(t, s.Shutdown(context.Background()))
}

func TestShutdownWaitsForInFlightDelivery(t *testing.T) {
	h := start(t, baseConfig())
	entered := make(chan struct{})
	release := make(chan struct{})
	h.del.fn = func(context.Context, *relay.Message) relay.Result {
		close(entered)
		<-release
		return relay.Result{Upstream: "up1", Attempts: []relay.Attempt{{Upstream: "up1"}}}
	}

	busy := dialRaw(t, h.addr(0))
	busy.greet()
	idle := dialRaw(t, h.addr(0))
	idle.greet()

	reply := make(chan string, 1)
	go func() { reply <- busy.sendMail("a@example.com", []string{"b@x.test"}, "Subject: s\r\n\r\nb") }()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutErr := make(chan error, 1)
	go func() { shutErr <- h.srv.Shutdown(ctx) }()

	// The idle connection is closed, new connections are refused, but Shutdown keeps waiting.
	idle.expectEOF()
	select {
	case err := <-shutErr:
		t.Fatalf("Shutdown returned early: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	_, err := net.DialTimeout("tcp", h.addr(0), time.Second)
	assert.Error(t, err)

	close(release)
	assert.True(t, strings.HasPrefix(<-reply, "250 "), "in-flight mail must complete")
	require.NoError(t, <-shutErr)

	_, done, _ := h.ev.snapshot()
	assert.Len(t, done, 1)
	live, _ := h.ev.liveCount()
	assert.Zero(t, live)
}

func TestShutdownExpiredContextForcesClose(t *testing.T) {
	h := start(t, baseConfig())
	entered := make(chan struct{})
	delivered := make(chan struct{})
	h.del.fn = func(ctx context.Context, _ *relay.Message) relay.Result {
		close(entered)
		<-ctx.Done()
		close(delivered)
		return relay.Result{Err: ctx.Err()}
	}
	c := dialRaw(t, h.addr(0))
	c.greet()
	_, err := fmt.Fprint(c.conn, "MAIL FROM:<a@example.com>\r\nRCPT TO:<b@x.test>\r\nDATA\r\nSubject: s\r\n\r\nb\r\n.\r\n")
	require.NoError(t, err)
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	begin := time.Now()
	err = h.srv.Shutdown(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(begin), 3*time.Second)

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery context was not cancelled")
	}
	require.Eventually(t, func() bool { live, _ := h.ev.liveCount(); return live == 0 }, 2*time.Second, 10*time.Millisecond)
}

func TestConnEventsBalancedAfterBurst(t *testing.T) {
	h := start(t, baseConfig(), func(c *Config) { c.Server.Limits.MaxConnections = -1 })
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", h.addr(0), 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			r := textproto.NewReader(bufio.NewReader(conn))
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = r.ReadLine()
			if i%2 == 0 {
				fmt.Fprintf(conn, "QUIT\r\n")
				_, _ = r.ReadLine()
			}
		}()
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		live, _ := h.ev.liveCount()
		return live == 0
	}, 5*time.Second, 10*time.Millisecond)
	live, min := h.ev.liveCount()
	assert.Zero(t, live)
	assert.GreaterOrEqual(t, min, 0, "ConnClosed must never outrun ConnAccepted")
	h.ev.mu.Lock()
	defer h.ev.mu.Unlock()
	assert.Equal(t, n, h.ev.accepted["127.0.0.1:0"])
	assert.Equal(t, n, h.ev.closed["127.0.0.1:0"])
}
