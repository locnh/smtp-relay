package maillog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func baseSummary() Summary {
	return Summary{
		ID: "3f1c-uuid", Peer: "192.168.1.20", From: "alerts@example.com",
		To: []string{"ops@example.com"}, Subject: "Disk usage 91% on db01",
		Status: StatusDelivered, Upstream: "ses-eu", Attempts: 1, Size: 2048,
		Duration: 420 * time.Millisecond,
	}
}

func logJSON(t *testing.T, s Summary) (map[string]any, string) {
	t.Helper()
	var buf bytes.Buffer
	Log(zerolog.New(&buf), s)
	out := buf.String()
	require.Equal(t, 1, strings.Count(out, "\n"), "exactly one line: %q", out)
	require.True(t, strings.HasSuffix(out, "\n"))
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &m))
	return m, out
}

func TestLogDelivered(t *testing.T) {
	m, out := logJSON(t, baseSummary())
	assert.Equal(t, map[string]any{
		"level": "info", "message": "mail",
		"from": "alerts@example.com", "to": []any{"ops@example.com"},
		"subj": "Disk usage 91% on db01", "status": "delivered", "upstream": "ses-eu",
		"attempts": float64(1), "size": float64(2048), "duration_ms": float64(420),
		"peer": "192.168.1.20", "uuid": "3f1c-uuid",
	}, m)

	order := []string{`"from"`, `"to"`, `"subj"`, `"status"`, `"upstream"`, `"attempts"`, `"size"`, `"duration_ms"`, `"peer"`, `"uuid"`}
	last := -1
	for _, k := range order {
		i := strings.Index(out, k)
		require.Greater(t, i, last, "field %s out of order in %s", k, out)
		last = i
	}
}

func TestLogFailed(t *testing.T) {
	s := baseSummary()
	s.Status, s.Upstream, s.Attempts = StatusFailed, "", 2
	s.Err = errors.New("smtp2go: 535 authentication failed")
	m, _ := logJSON(t, s)
	assert.Equal(t, "error", m["level"])
	assert.Equal(t, "failed", m["status"])
	assert.Equal(t, "smtp2go: 535 authentication failed", m["error"])
	assert.NotContains(t, m, "upstream")
	assert.Equal(t, float64(2), m["attempts"])
}

func TestLogOmitsOptionalFields(t *testing.T) {
	m, _ := logJSON(t, baseSummary())
	assert.NotContains(t, m, "error")
	assert.NotContains(t, m, "rcpt_count")
}

func TestLogRecipientCap(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		wantTo    int
		wantCount bool
	}{
		{"none", 0, 0, false},
		{"ten", 10, 10, false},
		{"eleven", 11, 10, true},
		{"many", 250, 10, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSummary()
			s.To = nil
			for i := 0; i < tt.n; i++ {
				s.To = append(s.To, fmt.Sprintf("u%d@example.com", i))
			}
			m, _ := logJSON(t, s)
			assert.Len(t, m["to"], tt.wantTo)
			if tt.wantCount {
				assert.Equal(t, float64(tt.n), m["rcpt_count"])
			} else {
				assert.NotContains(t, m, "rcpt_count")
			}
			if tt.n > 0 {
				assert.Equal(t, "u0@example.com", m["to"].([]any)[0])
			}
		})
	}
}

func TestLogSanitises(t *testing.T) {
	s := baseSummary()
	s.From = "a@b>\r\nINF mail from=evil"
	s.To = []string{"x@y\ninjected", "ok@z"}
	s.Peer = "1.2.3.4\r\n"
	s.Subject = "hi\r\nINF mail status=delivered\x1b[0m"
	s.Status = StatusFailed
	s.Err = errors.New("550 bad\r\nERR mail fake")
	m, out := logJSON(t, s)

	assert.Equal(t, "a@b>  INF mail from=evil", m["from"])
	assert.Equal(t, []any{"x@y injected", "ok@z"}, m["to"])
	assert.Equal(t, "1.2.3.4  ", m["peer"])
	assert.Equal(t, "hi  INF mail status=delivered [0m", m["subj"])
	assert.Equal(t, "550 bad  ERR mail fake", m["error"])
	assert.NotContains(t, out, `\r`)
	assert.NotContains(t, out, `\n"`)
}

func TestLogTruncatesSubjectDefensively(t *testing.T) {
	s := baseSummary()
	s.Subject = strings.Repeat("é", 500)
	m, _ := logJSON(t, s)
	assert.Equal(t, strings.Repeat("é", 200)+"…", m["subj"])

	s.Subject = Subject([]byte("Subject: " + strings.Repeat("é", 500) + "\r\n\r\n"))
	m, _ = logJSON(t, s)
	assert.Equal(t, strings.Repeat("é", 200)+"…", m["subj"])
}

func TestLogNoExtraFields(t *testing.T) {
	s := baseSummary()
	s.Status = StatusFailed
	s.Err = errors.New("boom")
	s.To = make([]string, 12)
	m, _ := logJSON(t, s)
	allowed := map[string]bool{
		"level": true, "message": true, "from": true, "to": true, "rcpt_count": true, "subj": true,
		"status": true, "upstream": true, "attempts": true, "size": true, "duration_ms": true,
		"peer": true, "uuid": true, "error": true,
	}
	for k := range m {
		assert.True(t, allowed[k], "unexpected field %q", k)
	}
}

func TestLogConsoleWriterSingleLine(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Summary)
		want []string
	}{
		{"delivered", func(*Summary) {}, []string{"INF", "mail", "from=alerts@example.com", "status=delivered", "upstream=ses-eu"}},
		{"failed with injection", func(s *Summary) {
			s.Status, s.Upstream = StatusFailed, ""
			s.Subject = "Backup failed\r\n2026 INF mail from=evil"
			s.Err = errors.New("smtp2go: 535\nauthentication failed")
		}, []string{"ERR", "mail", "status=failed", "error="}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := zerolog.New(zerolog.ConsoleWriter{Out: &buf, NoColor: true, TimeFormat: time.RFC3339})
			s := baseSummary()
			tt.mod(&s)
			Log(l, s)
			out := buf.String()
			assert.Equal(t, 1, strings.Count(out, "\n"), out)
			for _, w := range tt.want {
				assert.Contains(t, out, w)
			}
		})
	}
}
