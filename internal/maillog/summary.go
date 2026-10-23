package maillog

import (
	"time"

	"github.com/rs/zerolog"
)

const maxRecipients = 10

type Status string

const (
	StatusDelivered Status = "delivered"
	StatusFailed    Status = "failed"
)

// Summary describes the outcome of one mail whose DATA was fully received.
type Summary struct {
	ID       string
	Peer     string
	From     string
	To       []string
	Subject  string
	Status   Status
	Upstream string
	Attempts int
	Size     int
	Duration time.Duration
	Err      error
}

// Log writes exactly one line for the summary: info when delivered, error when failed.
// Every free-form value is sanitised so it cannot forge additional log lines.
func Log(l zerolog.Logger, s Summary) {
	ev := l.Info()
	if s.Status == StatusFailed {
		ev = l.Error()
	}

	to := s.To
	if len(to) > maxRecipients {
		to = to[:maxRecipients]
	}
	rcpts := make([]string, len(to))
	for i, a := range to {
		rcpts[i] = Sanitize(a)
	}

	ev = ev.Str("from", Sanitize(s.From)).Strs("to", rcpts)
	if len(s.To) > maxRecipients {
		ev = ev.Int("rcpt_count", len(s.To))
	}
	ev = ev.Str("subj", truncate(Sanitize(s.Subject), maxSubjectLen)).
		Str("status", string(s.Status))
	if s.Upstream != "" {
		ev = ev.Str("upstream", Sanitize(s.Upstream))
	}
	ev = ev.Int("attempts", s.Attempts).
		Int("size", s.Size).
		Int64("duration_ms", s.Duration.Milliseconds()).
		Str("peer", Sanitize(s.Peer)).
		Str("uuid", Sanitize(s.ID))
	if s.Err != nil {
		ev = ev.Str("error", Sanitize(s.Err.Error()))
	}
	ev.Msg("mail")
}
