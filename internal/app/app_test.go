package app

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/locnh/smtp-relay/internal/config"
)

// fakeUpstream is a minimal SMTP server that records what it receives.
type fakeUpstream struct {
	ln       net.Listener
	user     string
	pass     string
	dataCode string        // reply to end-of-DATA, default "250 queued"
	inData   chan struct{} // closed-on-first-use signal that DATA was received
	release  chan struct{} // when non-nil, end-of-DATA reply waits for it
	once     sync.Once

	mu    sync.Mutex
	mails []recorded
}

type recorded struct {
	from string
	to   []string
	data string
}

func startFakeUpstream(t *testing.T, user, pass, dataReply string) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeUpstream{ln: ln, user: user, pass: pass, dataCode: dataReply}
	if f.dataCode == "" {
		f.dataCode = "250 queued"
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeUpstream) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeUpstream) received() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.mails...)
}

func addrOf(line string) string {
	i, j := strings.Index(line, "<"), strings.LastIndex(line, ">")
	if i < 0 || j < i {
		return ""
	}
	return line[i+1 : j]
}

func (f *fakeUpstream) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	send := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	send("220 fake ESMTP")
	var cur recorded
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			if f.user != "" {
				send("250-fake")
				send("250 AUTH PLAIN")
			} else {
				send("250 fake")
			}
		case strings.HasPrefix(verb, "AUTH PLAIN "):
			raw, _ := base64.StdEncoding.DecodeString(line[len("AUTH PLAIN "):])
			if string(raw) == "\x00"+f.user+"\x00"+f.pass {
				send("235 2.7.0 ok")
			} else {
				send("535 5.7.8 bad credentials")
			}
		case strings.HasPrefix(verb, "MAIL FROM:"):
			cur = recorded{from: addrOf(line)}
			send("250 ok")
		case strings.HasPrefix(verb, "RCPT TO:"):
			cur.to = append(cur.to, addrOf(line))
			send("250 ok")
		case verb == "DATA":
			send("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			cur.data = b.String()
			if f.release != nil {
				f.once.Do(func() { close(f.inData) })
				<-f.release
			}
			if strings.HasPrefix(f.dataCode, "250") {
				f.mu.Lock()
				f.mails = append(f.mails, cur)
				f.mu.Unlock()
			}
			send(f.dataCode)
		case verb == "QUIT":
			send("221 bye")
			return
		default:
			send("250 ok")
		}
	}
}

// closedPort returns a TCP port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return p
}

type upSpec struct {
	name  string
	port  int
	user  string
	pass  string
	quota int // 0 = none
}

type cfgSpec struct {
	upstreams []upSpec
	smtpAddr  string // default 127.0.0.1:0
	nets      string // YAML flow list, default [127.0.0.0/8]
	senders   string // YAML flow list, default omitted
	metrics   string // address; "" = disabled
	state     string
	shutdown  string
	logPath   string
}

func (s cfgSpec) yaml() string {
	var b strings.Builder
	if s.smtpAddr == "" {
		s.smtpAddr = "127.0.0.1:0"
	}
	if s.nets == "" {
		s.nets = "[127.0.0.0/8]"
	}
	if s.shutdown == "" {
		s.shutdown = "5s"
	}
	fmt.Fprintf(&b, "server:\n  hostname: relay.test\n  listen: [{address: \"%s\", tls: none}]\n  timeouts: {shutdown: %s}\n", s.smtpAddr, s.shutdown)
	fmt.Fprintf(&b, "access:\n  allowed_networks: %s\n", s.nets)
	if s.senders != "" {
		fmt.Fprintf(&b, "  allowed_senders: %s\n", s.senders)
	}
	b.WriteString("upstreams:\n")
	for _, u := range s.upstreams {
		fmt.Fprintf(&b, "  - name: %s\n    host: 127.0.0.1\n    port: %d\n    tls: none\n    timeouts: {connect: 2s, command: 5s, data: 5s}\n", u.name, u.port)
		if u.user != "" {
			fmt.Fprintf(&b, "    auth: {username: %s, password: %s, allow_insecure_auth: true}\n", u.user, u.pass)
		}
		if u.quota > 0 {
			fmt.Fprintf(&b, "    quota: {limit: %d, window: 24h}\n", u.quota)
		}
	}
	if s.state != "" {
		fmt.Fprintf(&b, "state:\n  file: %s\n", s.state)
	}
	fmt.Fprintf(&b, "logging:\n  level: debug\n  format: json\n  output: file\n  file: {path: %s}\n", s.logPath)
	if s.metrics != "" {
		fmt.Fprintf(&b, "metrics:\n  enabled: true\n  listen: \"%s\"\n", s.metrics)
	}
	return b.String()
}

func loadCfg(t *testing.T, s cfgSpec) *config.Config {
	t.Helper()
	if s.logPath == "" {
		s.logPath = filepath.Join(t.TempDir(), "logs", "relay.log")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(s.yaml()), 0o600))
	cfg, err := config.Load(p)
	require.NoError(t, err)
	return cfg
}

type harness struct {
	t       *testing.T
	app     *App
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	logPath string
}

func start(t *testing.T, s cfgSpec) *harness {
	t.Helper()
	if s.logPath == "" {
		s.logPath = filepath.Join(t.TempDir(), "logs", "relay.log")
	}
	a, err := New(loadCfg(t, s), "test")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, app: a, cancel: cancel, done: make(chan struct{}), logPath: s.logPath}
	go func() {
		h.err = a.Run(ctx)
		close(h.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
		}
	})
	require.Eventually(t, func() bool {
		return len(a.Addrs()) > 0 && (s.metrics == "" || a.MetricsAddr() != nil)
	}, 5*time.Second, 5*time.Millisecond)
	return h
}

func (h *harness) stop() error {
	h.t.Helper()
	h.cancel()
	select {
	case <-h.done:
		return h.err
	case <-time.After(10 * time.Second):
		h.t.Fatal("Run did not return after cancel")
		return nil
	}
}

func (h *harness) smtpAddr() string { return h.app.Addrs()[0].String() }

func (h *harness) send(from string, to []string, msg string) error {
	return smtp.SendMail(h.smtpAddr(), nil, from, to, []byte(msg))
}

func (h *harness) scrape() string {
	h.t.Helper()
	return httpGet(h.t, "http://"+h.app.MetricsAddr().String()+"/metrics")
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	_, body := httpStatus(t, url)
	return body
}

func httpStatus(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// metric returns the value of an exact series such as `name{a="b"}`.
func metric(t *testing.T, body, series string) float64 {
	t.Helper()
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, series+" ") {
			v, err := strconv.ParseFloat(strings.TrimPrefix(l, series+" "), 64)
			require.NoError(t, err)
			return v
		}
	}
	t.Fatalf("series %s not found in metrics", series)
	return 0
}

func logLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m), l)
		out = append(out, m)
	}
	return out
}

func filterLog(lines []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["message"] == msg {
			out = append(out, l)
		}
	}
	return out
}

const testMail = "From: <alerts@example.com>\r\nTo: <ops@example.com>\r\nSubject: Disk usage 91%\r\n\r\nline one\r\n.dot line\r\nlast\r\n"

func TestEndToEndHappyPath(t *testing.T) {
	up := startFakeUpstream(t, "relayuser", "s3cretpw", "")
	logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
	h := start(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port(), user: "relayuser", pass: "s3cretpw"}},
		logPath:   logPath,
	})

	require.NoError(t, h.send("alerts@example.com", []string{"ops@example.com", "dev@example.com"}, testMail))

	got := up.received()
	require.Len(t, got, 1)
	assert.Equal(t, "alerts@example.com", got[0].from)
	assert.Equal(t, []string{"ops@example.com", "dev@example.com"}, got[0].to)
	assert.Equal(t, testMail, got[0].data)

	require.NoError(t, h.stop())
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "s3cretpw")

	summaries := filterLog(logLines(t, logPath), "mail")
	require.Len(t, summaries, 1)
	s := summaries[0]
	assert.Equal(t, "alerts@example.com", s["from"])
	assert.Equal(t, []any{"ops@example.com", "dev@example.com"}, s["to"])
	assert.Equal(t, "Disk usage 91%", s["subj"])
	assert.Equal(t, "delivered", s["status"])
	assert.Equal(t, "primary", s["upstream"])
	assert.EqualValues(t, 1, s["attempts"])
	assert.NotEmpty(t, s["uuid"])
	assert.Empty(t, filterLog(logLines(t, logPath), "upstream failed"))
}

func TestEndToEndFailover(t *testing.T) {
	second := startFakeUpstream(t, "", "", "")
	logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
	h := start(t, cfgSpec{
		upstreams: []upSpec{{name: "first", port: closedPort(t)}, {name: "second", port: second.port()}},
		metrics:   "127.0.0.1:0",
		logPath:   logPath,
	})

	require.NoError(t, h.send("alerts@example.com", []string{"ops@example.com"}, testMail))
	require.Len(t, second.received(), 1)
	assert.Equal(t, testMail, second.received()[0].data)

	body := h.scrape()
	assert.EqualValues(t, 1, metric(t, body, `smtp_relay_upstream_failover_total{from="first",to="second"}`))
	assert.EqualValues(t, 1, metric(t, body, `smtp_relay_upstream_deliveries_total{error_class="connect",result="failure",upstream="first"}`))
	assert.EqualValues(t, 1, metric(t, body, `smtp_relay_upstream_deliveries_total{error_class="none",result="success",upstream="second"}`))
	assert.EqualValues(t, 1, metric(t, body, `smtp_relay_messages_received_total{reason="",result="delivered"}`))

	require.NoError(t, h.stop())
	lines := logLines(t, logPath)
	failed := filterLog(lines, "upstream failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "warn", failed[0]["level"])
	assert.Equal(t, "first", failed[0]["upstream"])
	assert.Equal(t, "connect", failed[0]["error_class"])
	assert.NotEmpty(t, failed[0]["uuid"])
	assert.NotEmpty(t, failed[0]["error"])

	summaries := filterLog(lines, "mail")
	require.Len(t, summaries, 1)
	assert.EqualValues(t, 2, summaries[0]["attempts"])
	assert.Equal(t, "second", summaries[0]["upstream"])
	assert.Equal(t, failed[0]["uuid"], summaries[0]["uuid"])
}

func TestAllUpstreamsFail(t *testing.T) {
	tests := []struct {
		name     string
		last     func(t *testing.T) int
		wantCode int
	}{
		{"connect failure", closedPort, 421},
		{"upstream 5xx kept", func(t *testing.T) int {
			return startFakeUpstream(t, "", "", "554 5.7.1 rejected by policy").port()
		}, 554},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
			h := start(t, cfgSpec{
				upstreams: []upSpec{{name: "first", port: closedPort(t)}, {name: "last", port: tt.last(t)}},
				metrics:   "127.0.0.1:0",
				logPath:   logPath,
			})

			err := h.send("alerts@example.com", []string{"ops@example.com"}, testMail)
			var te *textproto.Error
			require.ErrorAs(t, err, &te)
			assert.Equal(t, tt.wantCode, te.Code)
			assert.NotContains(t, te.Msg, "127.0.0.1")

			body := h.scrape()
			assert.EqualValues(t, 1, metric(t, body, `smtp_relay_messages_received_total{reason="upstream_error",result="failed"}`))

			require.NoError(t, h.stop())
			summaries := filterLog(logLines(t, logPath), "mail")
			require.Len(t, summaries, 1)
			assert.Equal(t, "error", summaries[0]["level"])
			assert.Equal(t, "failed", summaries[0]["status"])
			assert.EqualValues(t, 2, summaries[0]["attempts"])
			assert.NotEmpty(t, summaries[0]["error"])
			assert.NotContains(t, summaries[0], "upstream")
		})
	}
}

func TestQuotaPersistsAcrossRestart(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	state := filepath.Join(t.TempDir(), "state", "state.json")
	spec := cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port(), quota: 10}},
		state:     state,
		metrics:   "127.0.0.1:0",
	}

	h := start(t, spec)
	for range 3 {
		require.NoError(t, h.send("alerts@example.com", []string{"ops@example.com"}, testMail))
	}
	body := h.scrape()
	assert.EqualValues(t, 3, metric(t, body, `smtp_relay_upstream_quota_used{upstream="primary"}`))
	assert.EqualValues(t, 30, metric(t, body, `smtp_relay_upstream_quota_used_percent{upstream="primary"}`))
	assert.EqualValues(t, 10, metric(t, body, `smtp_relay_upstream_quota_limit{upstream="primary"}`))
	require.NoError(t, h.stop())

	h2 := start(t, spec)
	body = h2.scrape()
	assert.EqualValues(t, 3, metric(t, body, `smtp_relay_upstream_quota_used{upstream="primary"}`))
	require.NoError(t, h2.stop())
}

func TestShutdown(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	h := start(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port()}},
		metrics:   "127.0.0.1:0",
		shutdown:  "3s",
	})
	smtpAddr, metricsAddr := h.smtpAddr(), h.app.MetricsAddr().String()

	code, _ := httpStatus(t, "http://"+metricsAddr+"/readyz")
	assert.Equal(t, http.StatusOK, code)

	started := time.Now()
	require.NoError(t, h.stop())
	assert.Less(t, time.Since(started), 3*time.Second)

	for _, addr := range []string{smtpAddr, metricsAddr} {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
		}
		assert.Error(t, err, "port %s still open", addr)
	}

	assert.NotPanics(t, func() {
		assert.Error(t, h.app.Run(context.Background()), "second Run must fail")
	})
}

func TestStartupFailureReleasesPorts(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()
	metricsPort := closedPort(t)
	metricsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(metricsPort))

	logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
	a, err := New(loadCfg(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port()}},
		smtpAddr:  busy.Addr().String(),
		metrics:   metricsAddr,
		logPath:   logPath,
	}), "test")
	require.NoError(t, err)

	err = a.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen")

	ln, err := net.Listen("tcp", metricsAddr)
	require.NoError(t, err, "metrics port must not be left bound")
	_ = ln.Close()
}

func TestMetricsPortConflictReleasesSMTP(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()

	a, err := New(loadCfg(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port()}},
		metrics:   busy.Addr().String(),
	}), "test")
	require.NoError(t, err)

	require.Error(t, a.Run(context.Background()))
	require.Eventually(t, func() bool {
		for _, ad := range a.Addrs() {
			if c, err := net.DialTimeout("tcp", ad.String(), 200*time.Millisecond); err == nil {
				_ = c.Close()
				return false
			}
		}
		return true
	}, 3*time.Second, 10*time.Millisecond)
}

func TestSenderDenied(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
	h := start(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port()}},
		senders:   "[ok@example.com]",
		metrics:   "127.0.0.1:0",
		logPath:   logPath,
	})

	err := h.send("evil@example.org", []string{"ops@example.com"}, testMail)
	var te *textproto.Error
	require.ErrorAs(t, err, &te)
	assert.Equal(t, 550, te.Code)
	assert.Empty(t, up.received())

	body := h.scrape()
	assert.EqualValues(t, 1, metric(t, body, `smtp_relay_messages_received_total{reason="sender_denied",result="rejected"}`))

	require.NoError(t, h.stop())
	assert.Empty(t, filterLog(logLines(t, logPath), "mail"))
}

func TestOpenRelayWarningLogged(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	logPath := filepath.Join(t.TempDir(), "logs", "relay.log")
	h := start(t, cfgSpec{
		upstreams: []upSpec{{name: "primary", port: up.port()}},
		nets:      "[]",
		logPath:   logPath,
	})
	require.NoError(t, h.stop())

	var found bool
	for _, l := range logLines(t, logPath) {
		if l["level"] == "warn" && strings.Contains(fmt.Sprint(l["message"]), "open relay") {
			found = true
		}
	}
	assert.True(t, found, "open relay warning missing from log")
}

func TestShutdownFinishesInFlightMail(t *testing.T) {
	up := startFakeUpstream(t, "", "", "")
	up.inData, up.release = make(chan struct{}), make(chan struct{})
	h := start(t, cfgSpec{upstreams: []upSpec{{name: "primary", port: up.port()}}})

	sendErr := make(chan error, 1)
	go func() {
		// smtp.SendMail would also report the EOF from QUIT when the server
		// closes the connection right after 250, so drive the client by hand.
		c, err := smtp.Dial(h.smtpAddr())
		if err == nil {
			err = sendOn(c, "alerts@example.com", "ops@example.com", testMail)
		}
		sendErr <- err
	}()
	<-up.inData

	h.cancel()
	select {
	case <-h.done:
		t.Fatal("Run returned while a mail was still in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(up.release)

	require.NoError(t, <-sendErr)
	select {
	case <-h.done:
		assert.NoError(t, h.err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the in-flight mail finished")
	}
	assert.Len(t, up.received(), 1)
}

func sendOn(c *smtp.Client, from, to, msg string) error {
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	return w.Close()
}
