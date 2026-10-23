// Package maillog builds the per-mail summary log line (spec 7.2).
package maillog

import (
	"bytes"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxHeaderBytes bounds how much of the message is ever inspected.
	maxHeaderBytes = 64 << 10
	maxSubjectLen  = 200
	ellipsis       = "…"
)

// Subject returns the decoded, sanitised Subject of a raw message (headers+body as received).
// It never fails: a missing or malformed header yields a best-effort string or "".
func Subject(data []byte) string {
	raw, ok := rawSubject(data)
	if !ok {
		return ""
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(raw)
	if err != nil {
		decoded = raw
	}
	return truncate(strings.TrimSpace(Sanitize(decoded)), maxSubjectLen)
}

// Sanitize removes control characters (incl. CR, LF, TAB, DEL, C1 range) so a value cannot forge log lines.
// Each one is replaced by a single space; invalid UTF-8 becomes U+FFFD.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i] + ellipsis
		}
		n++
	}
	return s
}

// rawSubject returns the unfolded, still-encoded value of the first Subject
// header found in the header section of data.
func rawSubject(data []byte) (string, bool) {
	if len(data) > maxHeaderBytes {
		data = data[:maxHeaderBytes]
	}
	var (
		value strings.Builder
		found bool
		inSub bool
	)
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if inSub {
				value.Write(line)
			}
			continue
		}
		if inSub {
			break
		}
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimRight(name, " \t")), "subject") {
			found, inSub = true, true
			value.Write(bytes.TrimLeft(rest, " \t"))
		}
	}
	return value.String(), found
}
