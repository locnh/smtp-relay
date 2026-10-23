package app

import (
	"github.com/rs/zerolog"

	"github.com/locnh/smtp-relay/internal/maillog"
	"github.com/locnh/smtp-relay/internal/metrics"
	"github.com/locnh/smtp-relay/internal/quota"
	"github.com/locnh/smtp-relay/internal/relay"
	"github.com/locnh/smtp-relay/internal/server"
	"github.com/locnh/smtp-relay/internal/upstream"
)

// observer feeds relay attempts to metrics and logs failures.
type observer struct {
	m   *metrics.Metrics
	log zerolog.Logger
}

var _ relay.Observer = observer{}

func (o observer) OnAttempt(msg *relay.Message, a relay.Attempt) {
	o.m.OnAttempt(msg, a)
	if a.Err == nil {
		o.log.Debug().Str("uuid", msg.ID).Str("upstream", a.Upstream).
			Int64("duration_ms", a.Duration.Milliseconds()).Msg("upstream accepted")
		return
	}
	class := a.Class
	if class == "" || class == upstream.ClassNone {
		class = upstream.ClassOf(a.Err)
	}
	o.log.Warn().Str("uuid", msg.ID).Str("upstream", a.Upstream).
		Str("error_class", string(class)).
		Str("error", maillog.Sanitize(a.Err.Error())).
		Msg("upstream failed")
}

func (o observer) OnFailover(msg *relay.Message, from, to string) {
	o.m.OnFailover(msg, from, to)
}

// events connects server events to logging, metrics and the quota counters.
type events struct {
	m   *metrics.Metrics
	q   *quota.Manager // may be nil
	log zerolog.Logger
}

var _ server.Events = events{}

func (e events) MessageRejected(reason string)        { e.m.MessageRejected(reason) }
func (e events) ConnAccepted(listener string)         { e.m.ConnAccepted(listener) }
func (e events) ConnClosed(listener string)           { e.m.ConnClosed(listener) }
func (e events) ConnRejected(listener, result string) { e.m.ConnRejected(listener, result) }
func (e events) MessageReceived(size int)             { e.m.ObserveMessageSize(size) }

func (e events) MessageDone(s maillog.Summary, res relay.Result) {
	maillog.Log(e.log, s)
	if !res.Delivered() {
		e.m.MessageFailed("upstream_error")
		return
	}
	e.m.MessageDelivered()
	if e.q != nil {
		e.q.Record(res.Upstream)
	}
}
