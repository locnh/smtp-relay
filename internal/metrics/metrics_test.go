package metrics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/locnh/smtp-relay/internal/quota"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/upstream"
)

type fakeQuota struct {
	mu       sync.Mutex
	statuses []quota.Status
	werrs    uint64
}

func (f *fakeQuota) Statuses() []quota.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]quota.Status(nil), f.statuses...)
}

func (f *fakeQuota) WriteErrors() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.werrs
}

func (f *fakeQuota) set(s []quota.Status, w uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses, f.werrs = s, w
}

func startServer(t *testing.T, m *Metrics, path string, ready func() bool) (*Server, string) {
	t.Helper()
	s := NewServer("127.0.0.1:0", path, m, ready)
	require.NoError(t, s.Start())
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s, "http://" + s.Addr().String()
}

func get(t *testing.T, url string) (int, http.Header, string) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, string(b)
}

func counter(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, mm := range mf.GetMetric() {
			got := map[string]string{}
			for _, l := range mm.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			if len(got) != len(labels) {
				continue
			}
			for k, v := range labels {
				if got[k] != v {
					continue next
				}
			}
			switch {
			case mm.Counter != nil:
				return mm.Counter.GetValue()
			case mm.Gauge != nil:
				return mm.Gauge.GetValue()
			case mm.Histogram != nil:
				return float64(mm.Histogram.GetSampleCount())
			}
		}
	}
	t.Fatalf("metric %s %v not found", name, labels)
	return 0
}

func TestScenario(t *testing.T) {
	m := New("v1.2.3", nil)
	fixed := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return fixed }

	msg := &relay.Message{ID: "0b0f7b2c-1111-2222-3333-444455556666", Peer: "10.1.2.3", From: "alice@example.com", To: []string{"bob@example.com"}}

	m.OnAttempt(msg, relay.Attempt{Upstream: "ses", Err: &upstream.Error{Class: upstream.ClassAuth}, Class: upstream.ClassAuth, Duration: 200 * time.Millisecond})
	m.OnFailover(msg, "ses", "backup")
	m.OnAttempt(msg, relay.Attempt{Upstream: "backup", Class: upstream.ClassNone, Duration: 2 * time.Second})
	m.OnAttempt(msg, relay.Attempt{Upstream: "ses", Err: errors.New("boom"), Duration: time.Second}) // class derived from error
	m.MessageDelivered()
	m.MessageRejected("sender_denied")
	m.MessageRejected("sender_denied")
	m.MessageRejected("size_exceeded")
	m.MessageFailed("upstream_error")
	m.ObserveMessageSize(2048)
	m.ObserveMessageSize(100)
	m.ConnAccepted("main")
	m.ConnAccepted("main")
	m.ConnClosed("main")
	m.ConnRejected("main", "denied_network")
	m.ConnRejected("main", "rejected_limit")
	m.ConnRejected("main", "rejected_limit")
	m.SetCertExpiry("server", time.Unix(1_800_000_000, 0))

	tests := []struct {
		name   string
		metric string
		labels map[string]string
		want   float64
	}{
		{"delivered", "smtp_relay_messages_received_total", map[string]string{"result": "delivered", "reason": ""}, 1},
		{"rejected sender", "smtp_relay_messages_received_total", map[string]string{"result": "rejected", "reason": "sender_denied"}, 2},
		{"rejected size", "smtp_relay_messages_received_total", map[string]string{"result": "rejected", "reason": "size_exceeded"}, 1},
		{"failed", "smtp_relay_messages_received_total", map[string]string{"result": "failed", "reason": "upstream_error"}, 1},
		{"ses auth failure", "smtp_relay_upstream_deliveries_total", map[string]string{"upstream": "ses", "result": "failure", "error_class": "auth"}, 1},
		{"ses other failure", "smtp_relay_upstream_deliveries_total", map[string]string{"upstream": "ses", "result": "failure", "error_class": "other"}, 1},
		{"backup success", "smtp_relay_upstream_deliveries_total", map[string]string{"upstream": "backup", "result": "success", "error_class": "none"}, 1},
		{"ses duration count", "smtp_relay_upstream_delivery_duration_seconds", map[string]string{"upstream": "ses"}, 2},
		{"backup duration count", "smtp_relay_upstream_delivery_duration_seconds", map[string]string{"upstream": "backup"}, 1},
		{"last success", "smtp_relay_upstream_last_success_timestamp_seconds", map[string]string{"upstream": "backup"}, 1_700_000_000},
		{"failover", "smtp_relay_upstream_failover_total", map[string]string{"from": "ses", "to": "backup"}, 1},
		{"build info", "smtp_relay_build_info", map[string]string{"version": "v1.2.3"}, 1},
		{"accepted", "smtp_relay_connections_total", map[string]string{"listener": "main", "result": "accepted"}, 2},
		{"denied", "smtp_relay_connections_total", map[string]string{"listener": "main", "result": "denied_network"}, 1},
		{"limit", "smtp_relay_connections_total", map[string]string{"listener": "main", "result": "rejected_limit"}, 2},
		{"active", "smtp_relay_connections_active", map[string]string{"listener": "main"}, 1},
		{"size count", "smtp_relay_message_size_bytes", map[string]string{}, 2},
		{"cert", "smtp_relay_tls_certificate_expiry_timestamp_seconds", map[string]string{"cert": "server"}, 1_800_000_000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, counter(t, m, tc.metric, tc.labels))
		})
	}

	// no success timestamp for an upstream that never succeeded
	_, _, body := scrape(t, m)
	assert.NotContains(t, body, `upstream_last_success_timestamp_seconds{upstream="ses"}`)
}

func scrape(t *testing.T, m *Metrics) (int, http.Header, string) {
	t.Helper()
	_, base := startServer(t, m, "", nil)
	return get(t, base+"/metrics")
}

func TestSizeHistogramBuckets(t *testing.T) {
	m := New("v", nil)
	m.ObserveMessageSize(1024)
	m.ObserveMessageSize(64 << 20)
	_, _, body := scrape(t, m)
	assert.Contains(t, body, `smtp_relay_message_size_bytes_bucket{le="1024"} 1`)
	assert.Contains(t, body, `smtp_relay_message_size_bytes_bucket{le="6.7108864e+07"} 2`)
}

func TestUnknownValuesMapToOther(t *testing.T) {
	m := New("v", nil)
	m.MessageRejected("bob@example.com")
	m.MessageFailed("10.0.0.1")
	m.ConnRejected("main", "weird")
	m.OnAttempt(&relay.Message{}, relay.Attempt{Upstream: "u", Err: errors.New("x"), Class: upstream.Class("a@b.c")})

	assert.Equal(t, 1.0, counter(t, m, "smtp_relay_messages_received_total", map[string]string{"result": "rejected", "reason": "other"}))
	assert.Equal(t, 1.0, counter(t, m, "smtp_relay_messages_received_total", map[string]string{"result": "failed", "reason": "other"}))
	assert.Equal(t, 1.0, counter(t, m, "smtp_relay_connections_total", map[string]string{"listener": "main", "result": "other"}))
	assert.Equal(t, 1.0, counter(t, m, "smtp_relay_upstream_deliveries_total", map[string]string{"upstream": "u", "result": "failure", "error_class": "other"}))
}

func TestQuotaGaugesAtScrapeTime(t *testing.T) {
	q := &fakeQuota{}
	q.set([]quota.Status{{Upstream: "ses", Used: 800, Limit: 1000}, {Upstream: "noquota", Used: 5, Limit: 0}}, 2)
	m := New("v", q)

	assert.Equal(t, 80.0, counter(t, m, "smtp_relay_upstream_quota_used_percent", map[string]string{"upstream": "ses"}))
	assert.Equal(t, 800.0, counter(t, m, "smtp_relay_upstream_quota_used", map[string]string{"upstream": "ses"}))
	assert.Equal(t, 1000.0, counter(t, m, "smtp_relay_upstream_quota_limit", map[string]string{"upstream": "ses"}))
	assert.Equal(t, 2.0, counter(t, m, "smtp_relay_quota_state_write_errors_total", map[string]string{}))

	q.set([]quota.Status{{Upstream: "ses", Used: 250, Limit: 1000}}, 3)
	assert.Equal(t, 25.0, counter(t, m, "smtp_relay_upstream_quota_used_percent", map[string]string{"upstream": "ses"}))
	assert.Equal(t, 3.0, counter(t, m, "smtp_relay_quota_state_write_errors_total", map[string]string{}))

	_, _, body := scrape(t, m)
	assert.Contains(t, body, "# TYPE smtp_relay_quota_state_write_errors_total counter")
	assert.NotContains(t, body, `upstream="noquota"`)

	q.set([]quota.Status{{Upstream: "ses", Used: 1500, Limit: 1000}}, 3)
	assert.Equal(t, 150.0, counter(t, m, "smtp_relay_upstream_quota_used_percent", map[string]string{"upstream": "ses"}))
}

func TestNoQuotaGauges(t *testing.T) {
	empty := New("v", &fakeQuota{})
	nilSrc := New("v", nil)

	_, _, body := scrape(t, empty)
	assert.NotContains(t, body, "smtp_relay_upstream_quota_")

	_, _, body = scrape(t, nilSrc)
	assert.NotContains(t, body, "smtp_relay_upstream_quota_")
	assert.NotContains(t, body, "smtp_relay_quota_state_write_errors_total")
}

func TestRuntimeCollectorsRegistered(t *testing.T) {
	_, _, body := scrape(t, New("v", nil))
	assert.Contains(t, body, "go_goroutines")
}

func TestTwoInstancesDoNotConflict(t *testing.T) {
	a, b := New("a", nil), New("b", nil)
	a.MessageDelivered()
	assert.Equal(t, 1.0, counter(t, a, "smtp_relay_messages_received_total", map[string]string{"result": "delivered", "reason": ""}))
	n, err := testutil.GatherAndCount(b.Registry(), "smtp_relay_messages_received_total")
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestNoEmailOrIPInExposition(t *testing.T) {
	m := New("v1", &fakeQuota{statuses: []quota.Status{{Upstream: "ses", Used: 1, Limit: 10}}})
	msg := &relay.Message{
		ID: "0b0f7b2c-1111-2222-3333-444455556666", Peer: "192.168.10.20",
		From: "alice@example.com", To: []string{"bob@example.com"}, Data: []byte("Subject: secret\r\n\r\nhi"),
	}
	m.OnAttempt(msg, relay.Attempt{Upstream: "ses", Duration: time.Millisecond})
	m.OnAttempt(msg, relay.Attempt{Upstream: "ses", Err: errors.New("dial 192.168.10.20: alice@example.com"), Duration: time.Millisecond})
	m.OnFailover(msg, "ses", "backup")
	m.MessageRejected("alice@example.com")
	m.ConnAccepted("main")
	m.ConnRejected("main", "192.168.10.20")

	_, _, body := scrape(t, m)
	var labels []string
	labelRe := regexp.MustCompile(`"([^"]*)"`)
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "smtp_relay_") {
			continue
		}
		for _, mm := range labelRe.FindAllStringSubmatch(line, -1) {
			labels = append(labels, mm[1])
		}
	}
	require.NotEmpty(t, labels)
	ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, l := range labels {
		assert.NotContains(t, l, "@")
		assert.False(t, ipRe.MatchString(l), "label %q looks like an IP", l)
	}
	assert.NotContains(t, body, "secret")
	assert.NotContains(t, body, "0b0f7b2c")
}

func TestHTTP(t *testing.T) {
	m := New("v", nil)
	var ready bool
	var mu sync.Mutex
	_, base := startServer(t, m, "", func() bool { mu.Lock(); defer mu.Unlock(); return ready })

	code, _, body := get(t, base+"/healthz")
	assert.Equal(t, 200, code)
	assert.Equal(t, "ok\n", body)

	code, _, _ = get(t, base+"/readyz")
	assert.Equal(t, 503, code)
	mu.Lock()
	ready = true
	mu.Unlock()
	code, _, _ = get(t, base+"/readyz")
	assert.Equal(t, 200, code)

	code, hdr, body := get(t, base+"/metrics")
	assert.Equal(t, 200, code)
	assert.Contains(t, hdr.Get("Content-Type"), "text/plain")
	assert.Contains(t, body, `smtp_relay_build_info{version="v"} 1`)

	code, _, _ = get(t, base+"/nope")
	assert.Equal(t, 404, code)

	for _, p := range []string{"/metrics", "/healthz", "/readyz"} {
		resp, err := http.Post(base+p, "text/plain", strings.NewReader("x"))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, p)
	}

	resp, err := http.Head(base + "/healthz")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestCustomPath(t *testing.T) {
	_, base := startServer(t, New("v", nil), "/custom", nil)
	code, _, _ := get(t, base+"/custom")
	assert.Equal(t, 200, code)
	code, _, _ = get(t, base+"/metrics")
	assert.Equal(t, 404, code)
	code, _, _ = get(t, base+"/readyz")
	assert.Equal(t, 200, code, "nil ready func means ready")
}

func TestInvalidPath(t *testing.T) {
	for _, p := range []string{"/healthz", "/readyz", "metrics"} {
		s := NewServer("127.0.0.1:0", p, New("v", nil), nil)
		assert.Error(t, s.Start(), p)
		assert.Nil(t, s.Addr())
	}
}

func TestShutdownStopsServing(t *testing.T) {
	s, base := startServer(t, New("v", nil), "", nil)
	code, _, _ := get(t, base+"/healthz")
	require.Equal(t, 200, code)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(ctx))

	client := http.Client{Timeout: time.Second}
	_, err := client.Get(base + "/healthz")
	assert.Error(t, err)
}

func TestShutdownBeforeStart(t *testing.T) {
	s := NewServer("127.0.0.1:0", "", New("v", nil), nil)
	assert.NoError(t, s.Shutdown(context.Background()))
}

func TestBindErrorReturned(t *testing.T) {
	s, _ := startServer(t, New("v", nil), "", nil)
	s2 := NewServer(s.Addr().String(), "", New("v", nil), nil)
	assert.Error(t, s2.Start())
}
