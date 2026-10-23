package maillog

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubject(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"plain", "From: a@b\r\nSubject: Disk usage 91% on db01\r\n\r\nbody", "Disk usage 91% on db01"},
		{"lf only line endings", "Subject: hello\n\nbody", "hello"},
		{"folded", "Subject: first part\r\n second part\r\n\tthird\r\nTo: x@y\r\n\r\n", "first part second part third"},
		{"base64 utf8", "Subject: =?UTF-8?B?SGVsbG8gd8O2cmxk?=\r\n\r\n", "Hello wörld"},
		{"qp utf8 lowercase", "Subject: =?utf-8?q?caf=C3=A9_ok?=\r\n\r\n", "café ok"},
		{"adjacent words", "Subject: =?UTF-8?B?SGVsbG8g?= =?UTF-8?B?d8O2cmxk?=\r\n\r\n", "Hello wörld"},
		{"adjacent words across fold", "Subject: =?UTF-8?Q?Hel?=\r\n =?UTF-8?Q?lo?=\r\n\r\n", "Hello"},
		{"mixed plain and encoded", "Subject: Re: =?UTF-8?Q?caf=C3=A9?= done\r\n\r\n", "Re: café done"},
		{"iso-8859-1", "Subject: =?ISO-8859-1?Q?caf=E9?=\r\n\r\n", "café"},
		{"unsupported charset kept", "Subject: =?X-UNKNOWN-9?Q?abc?=\r\n\r\n", "=?X-UNKNOWN-9?Q?abc?="},
		{"malformed encoded word", "Subject: =?UTF-8?B?!!!?= tail\r\n\r\n", "=?UTF-8?B?!!!?= tail"},
		{"header name case", "SUBJECT: upper\r\n\r\n", "upper"},
		{"header name mixed case", "sUbJeCt:lower\r\n\r\n", "lower"},
		{"missing subject", "From: a@b\r\nTo: c@d\r\n\r\nbody", ""},
		{"headers only no blank line", "From: a@b\r\nSubject: only", "only"},
		{"empty data", "", ""},
		{"nil-ish blank line first", "\r\nSubject: in body\r\n", ""},
		{"no colon garbage", "garbage without colon", ""},
		{"empty subject", "Subject:\r\n\r\n", ""},
		{"first subject wins", "Subject: one\r\nSubject: two\r\n\r\n", "one"},
		{"body subject ignored", "From: a@b\r\n\r\nSubject: in body\r\n", ""},
		{"similar header name ignored", "X-Subject: no\r\nSubjectX: no\r\nSubject: yes\r\n\r\n", "yes"},
		{"stops at next header", "Subject: a\r\nTo: b\r\n c\r\n\r\n", "a"},
		{"injection via fold", "Subject: x\r\n INF mail from=evil\r\n\r\n", "x INF mail from=evil"},
		{"injection via bare CR", "Subject: x\rINF mail from=evil\r\n\r\n", "x INF mail from=evil"},
		{"injection via encoded CRLF", "Subject: =?UTF-8?Q?x=0D=0AINF_mail?=\r\n\r\n", "x  INF mail"},
		{"control chars and ESC", "Subject: a\x1b[31mred\x00\x7f\u0085b\ttab\r\n\r\n", "a [31mred   b tab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Subject([]byte(tt.data))
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, "\n")
			assert.NotContains(t, got, "\r")
			assert.True(t, utf8.ValidString(got))
		})
	}
}

func TestSubjectTruncation(t *testing.T) {
	tests := []struct {
		name      string
		subject   string
		wantRunes int
		wantCut   bool
	}{
		{"exactly 200", strings.Repeat("a", 200), 200, false},
		{"201 ascii", strings.Repeat("a", 201), 201, true},
		{"long ascii", strings.Repeat("a", 5000), 201, true},
		{"multibyte exactly 200", strings.Repeat("é", 200), 200, false},
		{"multibyte long", strings.Repeat("日", 500), 201, true},
		{"emoji long", strings.Repeat("😀", 300), 201, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Subject([]byte("Subject: " + tt.subject + "\r\n\r\n"))
			require.True(t, utf8.ValidString(got))
			assert.Equal(t, tt.wantRunes, utf8.RuneCountInString(got))
			assert.Equal(t, tt.wantCut, strings.HasSuffix(got, "…"))
			if tt.wantCut {
				assert.Equal(t, []rune(tt.subject)[:200], []rune(got)[:200])
			}
		})
	}
}

func TestSubjectHeaderLargerThanCap(t *testing.T) {
	t.Run("subject beyond cap is not found", func(t *testing.T) {
		data := "X-Pad: " + strings.Repeat("p", maxHeaderBytes) + "\r\nSubject: late\r\n\r\n"
		assert.Equal(t, "", Subject([]byte(data)))
	})
	t.Run("huge folded subject is bounded", func(t *testing.T) {
		data := "Subject: s" + strings.Repeat("\r\n "+strings.Repeat("x", 1000), 200) + "\r\n\r\n"
		got := Subject([]byte(data))
		assert.Equal(t, 201, utf8.RuneCountInString(got))
		assert.True(t, strings.HasSuffix(got, "…"))
	})
	t.Run("cap cutting a multibyte sequence", func(t *testing.T) {
		data := "Subject: " + strings.Repeat("日", maxHeaderBytes) + "\r\n\r\n"
		got := Subject([]byte(data))
		assert.True(t, utf8.ValidString(got))
	})
}

func TestSanitize(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"clean", "hello wörld", "hello wörld"},
		{"crlf", "a\r\nb", "a  b"},
		{"tab", "a\tb", "a b"},
		{"del and c1", "a\x7fb\u0085c\u009fd", "a b c d"},
		{"esc", "\x1b[2J", " [2J"},
		{"line separators", "a\u2028b\u2029c", "a b c"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assert.Equal(t, tt.want, Sanitize(tt.in)) })
	}
}

func FuzzSubject(f *testing.F) {
	f.Add([]byte("Subject: =?UTF-8?B?SGk=?=\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		got := Subject(b)
		if !utf8.ValidString(got) || strings.ContainsAny(got, "\r\n\x00") || utf8.RuneCountInString(got) > maxSubjectLen+1 {
			t.Fatalf("bad subject %q", got)
		}
	})
}

func TestSubjectKeepsRawWhenAnyWordUndecodable(t *testing.T) {
	// mime.WordDecoder fails the whole header if one word is undecodable, so
	// even the valid word stays encoded. Deliberate, see Subject.
	data := "Subject: =?UTF-8?B?SGk=?= =?X-UNKNOWN-9?Q?abc?=\r\n\r\n"
	assert.Equal(t, "=?UTF-8?B?SGk=?= =?X-UNKNOWN-9?Q?abc?=", Subject([]byte(data)))
}

func TestSanitizeFormatChars(t *testing.T) {
	tests := []struct{ name, in, want string }{
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

func TestSubjectFormatChars(t *testing.T) {
	assert.Equal(t, "evil  txt", Subject([]byte("Subject: evil\u202e txt\r\n\r\n")))
	assert.Equal(t, "👨\u200d👩\u200d👧 family", Subject([]byte("Subject: 👨\u200d👩\u200d👧 family\r\n\r\n")))
	assert.Equal(t, "a b", Subject([]byte("Subject: a\u200bb\r\n\r\n")))
}
