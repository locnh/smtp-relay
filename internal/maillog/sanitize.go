package maillog

import (
	"strings"
	"unicode"
)

const (
	zwj  = '\u200d'
	zwnj = '\u200c'
)

// Sanitize removes control characters (incl. CR, LF, TAB, DEL, C1 range) so a value cannot forge log lines.
// Unicode format characters (category Cf: bidi overrides/isolates, zero-width space,
// word joiner, BOM, ...) are replaced as well, to stop Trojan-Source style log forging.
// ZWJ and ZWNJ are kept so emoji sequences and Indic/Persian text survive.
// Each replaced rune becomes a single space; invalid UTF-8 becomes U+FFFD.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == zwj || r == zwnj:
			return r
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
			return ' '
		}
		return r
	}, s)
}
