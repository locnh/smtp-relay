package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

// Session is one client connection. It deliberately does not implement
// smtp.AuthSession, so AUTH is never advertised (spec 6.1). go-smtp calls the
// methods of one session sequentially.
type Session struct {
	b    *backend
	conn *smtp.Conn
	gc   *gatedConn
	peer string
	log  zerolog.Logger

	from string
	to   []string
	// drop closes the connection once the pending reply has been written.
	drop bool
}

func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	if s.b.forceTLS {
		if _, ok := s.conn.TLSConnectionState(); !ok {
			return errTLSRequired
		}
	}
	if s.from != "" {
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
	s.from = from
	s.to = nil
	s.setBusy(true)
	return nil
}

// Rcpt enforces max_recipients here rather than via smtp.Server.MaxRecipients,
// because go-smtp then replies without calling the session and the rejection
// could not be reported to Events.
func (s *Session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if max := s.b.srv.maxRecipients; max > 0 && len(s.to) >= max {
		s.b.srv.events.MessageRejected("too_many_recipients")
		s.log.Warn().Str("peer", s.peer).Int("limit", max).Msg("too many recipients")
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      fmt.Sprintf("Maximum limit of %d recipients reached", max),
		}
	}
	s.to = append(s.to, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if s.from == "" || len(s.to) == 0 {
		return errBadSequence
	}
	srv := s.b.srv
	start := time.Now()

	// go-smtp only arms a per-line deadline and does not touch it while the
	// DATA payload is read, so this deadline bounds the whole phase and a
	// slow-drip client cannot hold the connection past it.
	if d := srv.dataTimeout; d > 0 {
		_ = s.conn.Conn().SetReadDeadline(start.Add(d))
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return s.dataReadError(err)
	}
	srv.events.MessageReceived(len(data))

	msg := &relay.Message{
		ID:   srv.newID(),
		Peer: s.peer,
		From: s.from,
		To:   append([]string(nil), s.to...),
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

func (s *Session) dataReadError(err error) error {
	switch {
	case errors.Is(err, smtp.ErrDataTooLarge):
		s.b.srv.events.MessageRejected("size_exceeded")
		s.log.Warn().Str("peer", s.peer).Str("sender_address", maillog.Sanitize(s.from)).
			Msg("message too large")
		return smtp.ErrDataTooLarge
	case isTimeout(err):
		s.drop = true
		s.log.Warn().Str("peer", s.peer).Msg("DATA phase timed out")
		return errDataTimeout
	default:
		s.drop = true
		return err
	}
}

// Reset is called by go-smtp after every transaction, whatever its outcome.
func (s *Session) Reset() {
	s.from = ""
	s.to = nil
	s.setBusy(false)
	if s.drop || s.b.srv.closing.Load() {
		// Not Conn.Close: go-smtp holds its lock while calling Reset.
		if s.gc != nil {
			_ = s.gc.Close()
		} else {
			_ = s.conn.Conn().Close()
		}
	}
}

func (s *Session) Logout() error { return nil }

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
