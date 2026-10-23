// Package relay delivers a message to the first upstream that accepts it,
// trying them in priority order (failover).
//
// This file defines the types shared with the server, metrics and app packages.
package relay

import (
	"context"
	"time"

	"github.com/locnh/smtp-relay/internal/upstream"
)

// Message is one mail accepted from a client. Data is the full DATA payload
// exactly as received (headers and body).
type Message struct {
	ID   string // UUIDv4, also used in logs
	Peer string // client IP
	From string // envelope MAIL FROM
	To   []string
	Data []byte
}

// Sender delivers one message to one upstream. *upstream.Sender implements it.
type Sender interface {
	Name() string
	Send(ctx context.Context, from string, to []string, data []byte) error
}

// Attempt is the outcome of trying one upstream.
type Attempt struct {
	Upstream string
	Err      error // nil on success
	Class    upstream.Class
	Duration time.Duration
}

// Result is the outcome of Deliver.
type Result struct {
	Upstream string    // upstream that accepted the mail; "" if none did
	Attempts []Attempt // in the order tried
	Err      error     // nil if delivered; otherwise the LAST attempt's error
}

// Delivered reports whether some upstream accepted the message.
func (r Result) Delivered() bool { return r.Err == nil && r.Upstream != "" }

// Observer receives events for logging and metrics. Implementations must be
// safe for concurrent use and must not block.
type Observer interface {
	// OnAttempt is called after every upstream attempt, success or failure.
	OnAttempt(msg *Message, a Attempt)
	// OnFailover is called when a mail moves from one upstream to the next.
	OnFailover(msg *Message, from, to string)
}

// NopObserver ignores all events.
type NopObserver struct{}

func (NopObserver) OnAttempt(*Message, Attempt)         {}
func (NopObserver) OnFailover(*Message, string, string) {}
