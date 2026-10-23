package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansi = regexp.MustCompile(`\x1b\[`)

func baseCfg(output, format string) config.LoggingConfig {
	return config.LoggingConfig{Level: "info", Format: format, Output: output}
}

func TestNewOutputAndFormat(t *testing.T) {
	t.Parallel()

	for _, output := range []string{"stdout", "stderr"} {
		for _, format := range []string{"json", "text"} {
			t.Run(output+"/"+format, func(t *testing.T) {
				t.Parallel()
				var stdout, stderr bytes.Buffer
				l, err := newWithWriters(baseCfg(output, format), &stdout, &stderr)
				require.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, l.Close()) })

				zl := l.Zerolog()
				zl.Info().Str("k", "v").Msg("hello")

				got := stdout.String()
				other := stderr.String()
				if output == "stderr" {
					got, other = other, got
				}
				assert.Empty(t, other)
				require.NotEmpty(t, got)
				assert.Contains(t, got, "hello")

				line := strings.TrimSpace(got)
				if format == "json" {
					var m map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &m))
					assert.Equal(t, "info", m["level"])
					assert.Equal(t, "hello", m["message"])
					assert.Equal(t, "v", m["k"])
					ts, ok := m["time"].(string)
					require.True(t, ok, "time field missing")
					_, err := time.Parse(time.RFC3339, ts)
					assert.NoError(t, err)
				} else {
					ts, _, _ := strings.Cut(line, " ")
					_, err := time.Parse(time.RFC3339, ts)
					assert.NoError(t, err, "text line must start with an RFC3339 timestamp")
					assert.NotRegexp(t, ansi, got)
				}
			})
		}
	}
}

func TestNewLevelFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		level   string
		logged  []string
		dropped []string
	}{
		{"error only", "error", []string{"error"}, []string{"warn", "info", "debug", "trace"}},
		{"warn", "warn", []string{"error", "warn"}, []string{"info", "debug", "trace"}},
		{"info", "info", []string{"error", "warn", "info"}, []string{"debug", "trace"}},
		{"trace", "trace", []string{"error", "warn", "info", "debug", "trace"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			cfg := baseCfg("stdout", "json")
			cfg.Level = tt.level
			l, err := newWithWriters(cfg, &stdout, &stderr)
			require.NoError(t, err)

			zl := l.Zerolog()
			for lvl, name := range map[zerolog.Level]string{
				zerolog.TraceLevel: "trace",
				zerolog.DebugLevel: "debug",
				zerolog.InfoLevel:  "info",
				zerolog.WarnLevel:  "warn",
				zerolog.ErrorLevel: "error",
			} {
				zl.WithLevel(lvl).Msg(name)
			}

			out := stdout.String()
			for _, want := range tt.logged {
				assert.Contains(t, out, `"message":"`+want+`"`)
			}
			for _, drop := range tt.dropped {
				assert.NotContains(t, out, `"message":"`+drop+`"`)
			}
		})
	}
}

func TestNewUnknownLevelWarnsAndUsesInfo(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	cfg := baseCfg("stdout", "json")
	cfg.Level = "verbose"
	l, err := newWithWriters(cfg, &stdout, &stderr)
	require.NoError(t, err)

	out := stdout.String()
	assert.Contains(t, out, `"level":"warn"`)
	assert.Contains(t, out, "unknown log level, using info")
	assert.Contains(t, out, `"configured_level":"verbose"`)

	zl := l.Zerolog()
	zl.Debug().Msg("hidden")
	zl.Info().Msg("shown")
	assert.NotContains(t, stdout.String(), "hidden")
	assert.Contains(t, stdout.String(), "shown")
}

func TestNewFileOutput(t *testing.T) {
	t.Parallel()

	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "relay.log")
			cfg := baseCfg("file", format)
			cfg.File = config.LoggingFileConfig{Path: path, MaxSizeMB: 1, MaxBackups: 1, MaxAgeDays: 1}

			var stdout, stderr bytes.Buffer
			l, err := newWithWriters(cfg, &stdout, &stderr)
			require.NoError(t, err)

			zl := l.Zerolog()
			zl.Info().Msg("to file")
			require.NoError(t, l.Close())

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Contains(t, string(data), "to file")
			assert.Empty(t, stdout.String())
			assert.Empty(t, stderr.String())

			assert.NoError(t, l.Close(), "second Close must be a no-op")
		})
	}
}

func TestCloseNoOpForStdout(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	l, err := newWithWriters(baseCfg("stdout", "json"), &stdout, &stderr)
	require.NoError(t, err)
	assert.NoError(t, l.Close())
	assert.NoError(t, l.Close())
}

func TestSecretNeverLogged(t *testing.T) {
	t.Parallel()

	secret := config.Secret("hunter2-super-secret")
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			l, err := newWithWriters(baseCfg("stdout", format), &stdout, &stderr)
			require.NoError(t, err)

			zl := l.Zerolog()
			zl.Info().Interface("password", secret).Str("pw", secret.String()).Msg("auth")

			out := stdout.String()
			assert.NotContains(t, out, "hunter2-super-secret")
			assert.Contains(t, out, "***")
		})
	}
}

func TestNewErrors(t *testing.T) {
	t.Parallel()

	unwritable := filepath.Join(t.TempDir(), "missing-dir", "relay.log")

	tests := []struct {
		name string
		cfg  config.LoggingConfig
	}{
		{"unknown output", config.LoggingConfig{Level: "info", Format: "json", Output: "syslog"}},
		{"unknown format", config.LoggingConfig{Level: "info", Format: "yaml", Output: "stdout"}},
		{"file without path", config.LoggingConfig{Level: "info", Format: "json", Output: "file"}},
		{"file in missing directory", config.LoggingConfig{
			Level: "info", Format: "json", Output: "file",
			File: config.LoggingFileConfig{Path: unwritable},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			l, err := newWithWriters(tt.cfg, &stdout, &stderr)
			assert.Nil(t, l)
			assert.Error(t, err)
		})
	}
}

func TestNewFileCompressDefault(t *testing.T) {
	t.Parallel()

	f := config.LoggingFileConfig{Path: filepath.Join(t.TempDir(), "relay.log")}
	rot, err := openRotator(f)
	require.NoError(t, err)
	assert.True(t, rot.Compress)
	require.NoError(t, rot.Close())

	off := false
	f.Compress = &off
	rot2, err := openRotator(f)
	require.NoError(t, err)
	assert.False(t, rot2.Compress)
	require.NoError(t, rot2.Close())
}

func TestNewEmptyLevelIsInfoWithoutWarning(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	cfg := baseCfg("stdout", "json")
	cfg.Level = ""
	l, err := newWithWriters(cfg, &stdout, &stderr)
	require.NoError(t, err)

	assert.Empty(t, stdout.String(), "empty level must not produce a warning")

	zl := l.Zerolog()
	zl.Debug().Msg("hidden")
	zl.Info().Msg("shown")
	assert.NotContains(t, stdout.String(), "hidden")
	assert.Contains(t, stdout.String(), "shown")
}

func TestNewBadFormatLeavesNoFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.LoggingConfig{
		Level: "info", Format: "yaml", Output: "file",
		File: config.LoggingFileConfig{Path: filepath.Join(dir, "relay.log")},
	}

	var stdout, stderr bytes.Buffer
	l, err := newWithWriters(cfg, &stdout, &stderr)
	assert.Nil(t, l)
	require.Error(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestNewFileMode(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on windows")
	}

	path := filepath.Join(t.TempDir(), "relay.log")
	cfg := baseCfg("file", "json")
	cfg.File = config.LoggingFileConfig{Path: path}

	var stdout, stderr bytes.Buffer
	l, err := newWithWriters(cfg, &stdout, &stderr)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestNewTextFieldsOrder(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	l, err := newWithWriters(baseCfg("stdout", "text"), &stdout, &stderr)
	require.NoError(t, err)

	zl := l.Zerolog()
	zl.Info().
		Str("uuid", "u-1").
		Str("error", "boom").
		Int("duration_ms", 5).
		Str("status", "delivered").
		Str("subj", "hi").
		Str("from", "a@example.com").
		Str("to", "b@example.com").
		Int("rcpt_count", 1).
		Str("peer", "10.0.0.1").
		Int("attempts", 1).
		Int("size", 42).
		Str("upstream", "ses").
		Msg("mail")

	line := stdout.String()
	keys := []string{"from=", "to=", "rcpt_count=", "subj=", "status=", "upstream=", "attempts=", "size=", "duration_ms=", "peer=", "uuid=", "error="}
	last := -1
	for _, k := range keys {
		idx := strings.Index(line, k)
		require.NotEqual(t, -1, idx, "missing %s in %q", k, line)
		assert.Greater(t, idx, last, "%s out of order in %q", k, line)
		last = idx
	}
}

func TestNewExistingFileModeUnchanged(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on windows")
	}

	tests := []struct {
		name string
		mode os.FileMode
	}{
		{"0644 kept", 0o644},
		{"0600 kept", 0o600},
		{"0666 kept", 0o666},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "relay.log")
			require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o600))
			require.NoError(t, os.Chmod(path, tt.mode))

			cfg := baseCfg("file", "json")
			cfg.File = config.LoggingFileConfig{Path: path}

			var stdout, stderr bytes.Buffer
			l, err := newWithWriters(cfg, &stdout, &stderr)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, l.Close()) })

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, tt.mode, info.Mode().Perm())
		})
	}
}

func TestNewExistingFileNeverChmodedOnStart(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on windows")
	}

	path := filepath.Join(t.TempDir(), "relay.log")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	cfg := baseCfg("file", "json")
	cfg.File = config.LoggingFileConfig{Path: path}

	var stdout, stderr bytes.Buffer
	l, err := newWithWriters(cfg, &stdout, &stderr)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "existing file mode must not be changed")
}
