package upstream

import (
	"errors"
	"net/smtp"
)

// errInsecureAuth is returned from Start, before any credential byte is
// produced, when the connection is not encrypted.
func errInsecureAuth(mech string) error {
	return &Error{
		Class: ClassAuth,
		Err:   errors.New("refusing to send " + mech + " credentials over an unencrypted connection"),
	}
}

// plainAuth implements AUTH PLAIN. Unlike net/smtp.PlainAuth it does not
// special-case localhost: the only exception is allowInsecure.
type plainAuth struct {
	username, password string
	allowInsecure      bool
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !a.allowInsecure {
		return "", nil, errInsecureAuth("PLAIN")
	}
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge during PLAIN")
	}
	return nil, nil
}

// loginAuth implements the (non-standard but widespread) AUTH LOGIN. The
// server asks for the username, then the password; prompts are not parsed
// because servers word them differently.
type loginAuth struct {
	username, password string
	allowInsecure      bool
	step               int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !a.allowInsecure {
		return "", nil, errInsecureAuth("LOGIN")
	}
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	}
	return nil, errors.New("unexpected extra server challenge during LOGIN")
}
