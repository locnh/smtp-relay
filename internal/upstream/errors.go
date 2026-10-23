// Package upstream sends mail to a real SMTP server over TLS with authentication.
//
// This file defines the error type shared by the sender, the relay (failover)
// and the metrics packages.
package upstream

import (
	"errors"
	"fmt"
)

// Class is a small, fixed set of failure categories. It is used as a metric
// label, so it must never grow unbounded.
type Class string

const (
	ClassNone    Class = "none"
	ClassConnect Class = "connect"
	ClassTLS     Class = "tls"
	ClassAuth    Class = "auth"
	ClassTimeout Class = "timeout"
	ClassSMTP4xx Class = "smtp_4xx"
	ClassSMTP5xx Class = "smtp_5xx"
	ClassOther   Class = "other"
)

// Error is the only error type Send returns on failure.
type Error struct {
	Class   Class
	Code    int    // SMTP reply code from the upstream, 0 if none
	Message string // SMTP reply text from the upstream, "" if none
	Err     error  // underlying cause
}

func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("%s: smtp %d: %s", e.Class, e.Code, e.Message)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Class, e.Err)
	}
	return string(e.Class)
}

func (e *Error) Unwrap() error { return e.Err }

// ClassOf returns the Class of err, or ClassOther if err is not an *Error.
// A nil error is ClassNone.
func ClassOf(err error) Class {
	if err == nil {
		return ClassNone
	}
	var ue *Error
	if errors.As(err, &ue) {
		return ue.Class
	}
	return ClassOther
}
