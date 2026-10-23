// Package metrics exposes Prometheus metrics and health endpoints.
//
// Every Metrics owns a private registry (never the default one), so many
// instances can coexist in tests. Label values are restricted to small fixed
// sets or configured names; never addresses, subjects or client IPs.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/locnh/smtp-relay/internal/quota"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/upstream"
)

const (
	namespace = "smtp_relay"
	other     = "other"
)

var (
	rejectReasons = setOf("sender_denied", "null_sender", "size_exceeded")
	failReasons   = setOf("upstream_error")
	connResults   = setOf("denied_network", "rejected_limit")
	errorClasses  = setOf(
		string(upstream.ClassConnect), string(upstream.ClassTLS), string(upstream.ClassAuth),
		string(upstream.ClassTimeout), string(upstream.ClassSMTP4xx), string(upstream.ClassSMTP5xx),
		string(upstream.ClassOther),
	)
)

func setOf(vals ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

func guard(set map[string]struct{}, v string) string {
	if _, ok := set[v]; ok {
		return v
	}
	return other
}

// QuotaSource provides quota state at scrape time. Statuses lists only the
// upstreams that have a quota.
type QuotaSource interface {
	Statuses() []quota.Status
	WriteErrors() uint64
}

// Metrics holds all collectors. It implements relay.Observer.
type Metrics struct {
	reg *prometheus.Registry
	now func() time.Time

	received     *prometheus.CounterVec
	deliveries   *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	lastSuccess  *prometheus.GaugeVec
	failovers    *prometheus.CounterVec
	connsTotal   *prometheus.CounterVec
	connsActive  *prometheus.GaugeVec
	messageSize  prometheus.Histogram
	certExpiry   *prometheus.GaugeVec
	buildInfoVec *prometheus.GaugeVec
}

var _ relay.Observer = (*Metrics)(nil)

// New creates a Metrics with its own registry. q may be nil, in which case no
// quota metrics are exposed.
func New(version string, q QuotaSource) *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), now: time.Now}

	m.received = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "messages_received_total",
		Help: "Messages received from clients, by outcome.",
	}, []string{"result", "reason"})
	m.deliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "upstream_deliveries_total",
		Help: "Delivery attempts per upstream.",
	}, []string{"upstream", "result", "error_class"})
	m.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "upstream_delivery_duration_seconds",
		Help:    "Duration of delivery attempts per upstream.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60},
	}, []string{"upstream"})
	m.lastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "upstream_last_success_timestamp_seconds",
		Help: "Unix time of the last successful delivery per upstream.",
	}, []string{"upstream"})
	m.failovers = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "upstream_failover_total",
		Help: "Failovers from one upstream to the next.",
	}, []string{"from", "to"})
	m.buildInfoVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Running version; always 1.",
	}, []string{"version"})
	m.connsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "connections_total",
		Help: "Client connections by result.",
	}, []string{"listener", "result"})
	m.connsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "connections_active",
		Help: "Currently open client connections.",
	}, []string{"listener"})
	m.messageSize = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Name: "message_size_bytes",
		Help:    "Size of accepted messages.",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 9), // 1KiB .. 64MiB
	})
	m.certExpiry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "tls_certificate_expiry_timestamp_seconds",
		Help: "Unix time at which a TLS certificate expires.",
	}, []string{"cert"})

	m.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.received, m.deliveries, m.duration, m.lastSuccess, m.failovers, m.buildInfoVec,
		m.connsTotal, m.connsActive, m.messageSize, m.certExpiry,
	)
	if q != nil {
		m.reg.MustRegister(newQuotaCollector(q))
	}

	m.buildInfoVec.WithLabelValues(version).Set(1)
	return m
}

// Registry returns the private registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// OnAttempt implements relay.Observer.
func (m *Metrics) OnAttempt(_ *relay.Message, a relay.Attempt) {
	result, class := "success", string(upstream.ClassNone)
	if a.Err != nil {
		result = "failure"
		c := a.Class
		if c == "" || c == upstream.ClassNone {
			c = upstream.ClassOf(a.Err)
		}
		class = guard(errorClasses, string(c))
	}
	m.deliveries.WithLabelValues(a.Upstream, result, class).Inc()
	m.duration.WithLabelValues(a.Upstream).Observe(a.Duration.Seconds())
	if a.Err == nil {
		m.lastSuccess.WithLabelValues(a.Upstream).Set(float64(m.now().Unix()))
	}
}

// OnFailover implements relay.Observer.
func (m *Metrics) OnFailover(_ *relay.Message, from, to string) {
	m.failovers.WithLabelValues(from, to).Inc()
}

func (m *Metrics) MessageDelivered() { m.received.WithLabelValues("delivered", "").Inc() }

func (m *Metrics) MessageRejected(reason string) {
	m.received.WithLabelValues("rejected", guard(rejectReasons, reason)).Inc()
}

func (m *Metrics) MessageFailed(reason string) {
	m.received.WithLabelValues("failed", guard(failReasons, reason)).Inc()
}

func (m *Metrics) ObserveMessageSize(bytes int) { m.messageSize.Observe(float64(bytes)) }

func (m *Metrics) ConnAccepted(listener string) {
	m.connsTotal.WithLabelValues(listener, "accepted").Inc()
	m.connsActive.WithLabelValues(listener).Inc()
}

func (m *Metrics) ConnClosed(listener string) { m.connsActive.WithLabelValues(listener).Dec() }

func (m *Metrics) ConnRejected(listener, result string) {
	m.connsTotal.WithLabelValues(listener, guard(connResults, result)).Inc()
}

// SetCertExpiry records a certificate's expiry; cert is e.g. "server" or "upstream:<name>".
func (m *Metrics) SetCertExpiry(cert string, notAfter time.Time) {
	m.certExpiry.WithLabelValues(cert).Set(float64(notAfter.Unix()))
}

// quotaCollector reads quota state at scrape time so values decay as the
// window slides.
type quotaCollector struct {
	src        QuotaSource
	usedPct    *prometheus.Desc
	used       *prometheus.Desc
	limit      *prometheus.Desc
	writeError *prometheus.Desc
}

func newQuotaCollector(src QuotaSource) *quotaCollector {
	d := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, "", name), help, labels, nil)
	}
	return &quotaCollector{
		src:        src,
		usedPct:    d("upstream_quota_used_percent", "Quota used as a percentage of the limit; may exceed 100.", "upstream"),
		used:       d("upstream_quota_used", "Messages counted inside the quota window.", "upstream"),
		limit:      d("upstream_quota_limit", "Configured quota limit.", "upstream"),
		writeError: d("quota_state_write_errors_total", "Failures writing the quota state file."),
	}
}

func (c *quotaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.usedPct
	ch <- c.used
	ch <- c.limit
	ch <- c.writeError
}

func (c *quotaCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.src.Statuses() {
		if s.Limit <= 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.usedPct, prometheus.GaugeValue, s.Percent(), s.Upstream)
		ch <- prometheus.MustNewConstMetric(c.used, prometheus.GaugeValue, float64(s.Used), s.Upstream)
		ch <- prometheus.MustNewConstMetric(c.limit, prometheus.GaugeValue, float64(s.Limit), s.Upstream)
	}
	ch <- prometheus.MustNewConstMetric(c.writeError, prometheus.CounterValue, float64(c.src.WriteErrors()))
}
