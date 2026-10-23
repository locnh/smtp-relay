package relay

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/locnh/smtp-relay/internal/upstream"
)

// ErrNoSenders is returned by Deliver when no upstream is configured.
var ErrNoSenders = errors.New("relay: no upstreams configured")

const maxReplyText = 200

// Relay tries its senders one at a time, in the order they were given.
// It keeps no state between calls, so it is safe for concurrent use.
type Relay struct {
	senders []Sender
	obs     Observer
}

// New returns a Relay that tries senders in the given order. A nil obs
// ignores all events.
func New(senders []Sender, obs Observer) *Relay {
	if obs == nil {
		obs = NopObserver{}
	}
	return &Relay{senders: append([]Sender(nil), senders...), obs: obs}
}

// Deliver sends msg through the first upstream that accepts it. It stops at
// the first success, so later upstreams never see a delivered message.
func (r *Relay) Deliver(ctx context.Context, msg *Message) Result {
	if len(r.senders) == 0 {
		return Result{Err: ErrNoSenders}
	}

	var res Result
	for i, s := range r.senders {
		// On cancellation Err becomes ctx.Err(); errors from earlier attempts stay in Attempts.
		if err := ctx.Err(); err != nil {
			res.Err = err
			return res
		}
		if i > 0 {
			r.obs.OnFailover(msg, r.senders[i-1].Name(), s.Name())
		}

		start := time.Now()
		err := s.Send(ctx, msg.From, msg.To, msg.Data)
		a := Attempt{
			Upstream: s.Name(),
			Err:      err,
			Class:    upstream.ClassOf(err),
			Duration: time.Since(start),
		}
		res.Attempts = append(res.Attempts, a)
		r.obs.OnAttempt(msg, a)

		if err == nil {
			res.Upstream = a.Upstream
			res.Err = nil
			return res
		}
		res.Err = err
	}
	return res
}

// Reply maps a failed Result to the SMTP reply the client should receive.
// Only genuine upstream 4xx/5xx replies keep their code and message. Every
// other failure (connect, TLS, auth, timeout, Err == nil) becomes
// 421 4.4.0 Forwarding failed, so callers must only call Reply on failed results.
// Hostnames and usernames never appear in the text.
func (r Result) Reply() (code int, enhanced [3]int, text string) {
	if errors.Is(r.Err, ErrNoSenders) {
		return 554, [3]int{5, 3, 0}, "No upstream configured"
	}
	var ue *upstream.Error
	if errors.As(r.Err, &ue) && ue.Code != 0 &&
		(ue.Class == upstream.ClassSMTP4xx || ue.Class == upstream.ClassSMTP5xx) {
		return ue.Code, [3]int{ue.Code / 100, 0, 0}, replyText(ue.Message)
	}
	return 421, [3]int{4, 4, 0}, "Forwarding failed"
}

// replyText makes an upstream message safe to put on a single SMTP reply line.
func replyText(s string) string {
	s = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(s))
	if utf8.RuneCountInString(s) > maxReplyText {
		s = strings.TrimSpace(string([]rune(s)[:maxReplyText]))
	}
	return s
}
