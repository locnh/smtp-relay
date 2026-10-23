package server

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/rs/zerolog"

	"github.com/locnh/smtp-relay/internal/maillog"
	"github.com/locnh/smtp-relay/internal/relay"
)

var (
	errSenderDenied = &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 7, 1},
		Message:      "Sender address not allowed",
	}
	errTLSRequired = &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Must issue a STARTTLS command first",
	}
	errDataTimeout = &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 4, 2},
		Message:      "Data timeout, closing connection",
	}
	errReadFailed = &smtp.SMTPError{
		Code:         451,
		EnhancedCode: smtp.EnhancedCode{4, 3, 0},
		Message:      "Error reading message",
	}
	errBadSequence = &smtp.SMTPError{
		Code:         503,
		EnhancedCode: smtp.EnhancedCode{5, 5, 1},
		Message:      "Bad sequence of commands",
	}
)

// backend creates one Session per SMTP connection for a single listener.
type backend struct {
	srv      *Server
	listener string
	forceTLS bool
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	nc := c.Conn()
	return &Session{
		b:    b,
		conn: c,
		gc:   findGated(nc),
		peer: peerIP(nc.RemoteAddr()),
		log:  b.srv.log.With().Str("listener", b.listener).Logger(),
	}, nil
}

// dataBackstopGrace delays the wall-clock backstop past the read deadline so
// that, for plain DATA, the deadline fires first and the client gets a clean 421.
const dataBackstopGrace = 250 * time.Millisecond

// Session is one client connection. It deliberately does not implement
// smtp.AuthSession, so AUTH is never advertised (spec 6.1).
//
// go-smtp calls the methods sequentially, except with BDAT (CHUNKING, which
// go-smtp always advertises): there Data runs in its own goroutine while the
// command loop keeps calling Mail, Rcpt and Reset. Hence mu, and Data works on
// copies of the envelope.
type Session struct {
	b    *backend
	conn *smtp.Conn
	gc   *gatedConn
	peer string
	log  zerolog.Logger

	mu   sync.Mutex
	from string
	to   []string
	// drop closes the connection once the pending reply has been written.
	drop atomic.Bool
}

func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	if s.b.forceTLS {
		if _, ok := s.conn.TLSConnectionState(); !ok {
			return errTLSRequired
		}
	}
	s.mu.Lock()
	pending := s.from != ""
	s.mu.Unlock()
	if pending {
		return errBadSequence
	}
	if from == "" || !s.b.srv.policy.SenderAllowed(from) {
		reason := "sender_denied"
		if from == "" {
			reason = "null_sender"
		}
		s.b.srv.events.MessageRejected(reason)
		s.log.Warn().Str("peer", s.peer).Str("sender_address", maillog.Sanitize(from)).
			Str("reason", reason).Msg("sender rejected")
		return errSenderDenied
	}
	s.mu.Lock()
	s.from = from
	s.to = nil
	s.mu.Unlock()
	s.setBusy(true)
	return nil
}

// Rcpt does no filtering (spec 6.1). max_recipients is enforced by go-smtp
// (452 4.5.3) without calling the session, so it is not reported as a rejected
// mail: the same mail may still be delivered with the recipients accepted so far.
func (s *Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.mu.Lock()
	s.to = append(s.to, to)
	s.mu.Unlock()
	return nil
}

// Data reads the whole message and delivers it.
//
// With BDAT go-smtp checks the size itself and replies 552 without calling the
// session, so no MessageRejected("size_exceeded") is emitted on that path; only
// plain DATA reports it.
func (s *Session) Data(r io.Reader) error {
	srv := s.b.srv
	srv.inflight.Add(1)
	defer srv.inflight.Add(-1)
	if s.gc != nil {
		s.gc.inflight.Add(1)
		defer s.gc.inflight.Add(-1)
	}

	s.mu.Lock()
	from, to := s.from, append([]string(nil), s.to...)
	s.mu.Unlock()
	if from == "" || len(to) == 0 {
		return errBadSequence
	}
	start := time.Now()

	// go-smtp only arms a per-line deadline and does not touch it while the
	// DATA payload is read, so this deadline bounds the whole phase. It cannot
	// help with BDAT, where every chunk command re-arms the per-line deadline
	// and this goroutine reads from a pipe, so the timer closing the connection
	// is the real bound there.
	var backstop *time.Timer
	// readState arbitrates between the timer and the end of the read: whoever
	// moves it from 0 first wins, so the timer never closes a connection whose
	// read already completed.
	var readState atomic.Int32
	const (
		readDone int32 = 1
		readCut  int32 = 2
	)
	if d := srv.dataTimeout; d > 0 {
		_ = s.conn.Conn().SetReadDeadline(start.Add(d))
		backstop = time.AfterFunc(d+dataBackstopGrace, func() {
			if readState.CompareAndSwap(0, readCut) {
				s.closeConn()
			}
		})
	}
	data, err := io.ReadAll(r)
	// Only the reading phase is bounded; delivery has its own timeouts.
	cut := false
	if backstop != nil {
		backstop.Stop()
		cut = !readState.CompareAndSwap(0, readDone)
	}
	if err != nil {
		if cut {
			s.log.Warn().Str("peer", s.peer).Msg("DATA phase timed out, connection closed")
		}
		return s.dataReadError(err, from)
	}
	if cut {
		s.log.Warn().Str("peer", s.peer).Msg("data timeout raced with a completed read")
	}
	srv.events.MessageReceived(len(data))

	msg := &relay.Message{
		ID:   srv.newID(),
		Peer: s.peer,
		From: from,
		To:   to,
		Data: data,
	}
	res := srv.deliverer.Deliver(srv.ctx, msg)

	status := maillog.StatusDelivered
	if !res.Delivered() {
		status = maillog.StatusFailed
	}
	srv.events.MessageDone(maillog.Summary{
		ID:       msg.ID,
		Peer:     msg.Peer,
		From:     msg.From,
		To:       msg.To,
		Subject:  maillog.Subject(data),
		Status:   status,
		Upstream: res.Upstream,
		Attempts: len(res.Attempts),
		Size:     len(data),
		Duration: time.Since(start),
		Err:      res.Err,
	}, res)

	if status == maillog.StatusDelivered {
		return nil
	}
	code, enh, text := res.Reply()
	return &smtp.SMTPError{Code: code, EnhancedCode: smtp.EnhancedCode(enh), Message: text}
}

func (s *Session) dataReadError(err error, from string) error {
	switch {
	case errors.Is(err, smtp.ErrDataTooLarge):
		s.b.srv.events.MessageRejected("size_exceeded")
		s.log.Warn().Str("peer", s.peer).Str("sender_address", maillog.Sanitize(from)).
			Msg("message too large")
		return smtp.ErrDataTooLarge
	case errors.Is(err, smtp.ErrDataReset):
		// RSET or disconnect during BDAT: the transaction was abandoned.
		return err
	case isTimeout(err):
		s.drop.Store(true)
		s.log.Warn().Str("peer", s.peer).Msg("DATA phase timed out")
		return errDataTimeout
	default:
		s.drop.Store(true)
		s.log.Debug().Err(err).Str("peer", s.peer).Msg("reading message failed")
		return errReadFailed
	}
}

// Reset is called by go-smtp after every transaction, whatever its outcome.
func (s *Session) Reset() {
	s.mu.Lock()
	s.from = ""
	s.to = nil
	s.mu.Unlock()
	s.setBusy(false)
	if s.drop.Load() || s.b.srv.closing.Load() {
		// Not Conn.Close: go-smtp holds its lock while calling Reset.
		s.closeConn()
	}
}

func (s *Session) Logout() error {
	s.setBusy(false)
	return nil
}

// closeConn closes the raw connection; gatedConn.Close is idempotent, so it is
// safe to race with go-smtp's own close.
func (s *Session) closeConn() {
	if s.gc != nil {
		_ = s.gc.Close()
		return
	}
	_ = s.conn.Conn().Close()
}

func (s *Session) setBusy(v bool) {
	if s.gc != nil {
		s.gc.busy.Store(v)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// findGated unwraps TLS layers to the admission wrapper of the raw connection.
func findGated(c net.Conn) *gatedConn {
	for c != nil {
		if gc, ok := c.(*gatedConn); ok {
			return gc
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		c = u.NetConn()
	}
	return nil
}
