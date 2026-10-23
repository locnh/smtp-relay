package maillog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitize(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"clean", "hello wörld", "hello wörld"},
		{"crlf", "a\r\nb", "a  b"},
		{"tab", "a\tb", "a b"},
		{"del and c1", "a\x7fb\u0085c\u009fd", "a b c d"},
		{"esc", "\x1b[2J", " [2J"},
		{"line separators", "a\u2028b\u2029c", "a b c"},
		{"empty", "", ""},
		{"rlo", "a\u202eb", "a b"},
		{"bidi embeddings", "\u202a\u202b\u202c\u202d\u202e", "     "},
		{"bidi isolates", "x\u2066y\u2067\u2068\u2069", "x y   "},
		{"zero width space", "a\u200bb", "a b"},
		{"word joiner", "a\u2060b", "a b"},
		{"bom", "\ufeffa", " a"},
		{"lrm rlm", "a\u200e\u200fb", "a  b"},
		{"zwj kept", "a\u200db", "a\u200db"},
		{"zwnj kept", "a\u200cb", "a\u200cb"},
		{"emoji family kept", "👨\u200d👩\u200d👧", "👨\u200d👩\u200d👧"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assert.Equal(t, tt.want, Sanitize(tt.in)) })
	}
}
