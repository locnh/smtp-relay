// Package logging builds the process logger from the logging configuration.
package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/DeRuina/timberjack"
	"github.com/locnh/smtp-relay/internal/config"
	"github.com/rs/zerolog"
)

// logFileMode keeps log files readable by the owner and group only, because
// they can contain mail Subjects.
const logFileMode os.FileMode = 0o640

// textFieldsOrder lists the per-mail summary fields (spec 7.2) in the order
// they should appear in text output.
var textFieldsOrder = []string{
	"from", "to", "rcpt_count", "subj", "status", "upstream",
	"attempts", "size", "duration_ms", "peer", "uuid", "error",
}

var levels = map[string]zerolog.Level{
	"trace": zerolog.TraceLevel,
	"debug": zerolog.DebugLevel,
	"info":  zerolog.InfoLevel,
	"warn":  zerolog.WarnLevel,
	"error": zerolog.ErrorLevel,
}

// Logger wraps a zerolog.Logger and, for file output, the rotating file it writes to.
type Logger struct {
	logger zerolog.Logger

	closeOnce sync.Once
	closer    io.Closer
	closeErr  error
}

// New builds a Logger for cfg. Output is exactly one of stdout, stderr or file.
// A file that cannot be opened is reported here, not on the first write.
func New(cfg config.LoggingConfig) (*Logger, error) {
	return newWithWriters(cfg, os.Stdout, os.Stderr)
}

func newWithWriters(cfg config.LoggingConfig, stdout, stderr io.Writer) (*Logger, error) {
	if cfg.Format != "json" && cfg.Format != "text" {
		return nil, fmt.Errorf("logging: unknown format %q (want text or json)", cfg.Format)
	}

	var (
		out    io.Writer
		closer io.Closer
	)
	switch cfg.Output {
	case "stdout":
		out = stdout
	case "stderr":
		out = stderr
	case "file":
		rot, err := openRotator(cfg.File)
		if err != nil {
			return nil, err
		}
		out = rot
		closer = rot
	default:
		return nil, fmt.Errorf("logging: unknown output %q (want stdout, stderr or file)", cfg.Output)
	}

	if cfg.Format == "text" {
		out = zerolog.ConsoleWriter{
			Out:         out,
			NoColor:     true,
			TimeFormat:  time.RFC3339,
			FieldsOrder: textFieldsOrder,
		}
	}

	base := zerolog.New(out).With().Timestamp().Logger()

	lvl, ok := levels[cfg.Level]
	if !ok {
		lvl = zerolog.InfoLevel
	}
	base = base.Level(lvl)
	if !ok && cfg.Level != "" {
		base.Warn().Str("configured_level", cfg.Level).Msg("unknown log level, using info")
	}

	return &Logger{logger: base, closer: closer}, nil
}

// Zerolog returns a value copy of the underlying logger.
func (l *Logger) Zerolog() zerolog.Logger {
	return l.logger
}

// Close flushes and closes the file rotator. It is a no-op for stdout and
// stderr and safe to call more than once. Writing after Close is not
// supported: the rotator would reopen the file.
func (l *Logger) Close() error {
	l.closeOnce.Do(func() {
		if l.closer != nil {
			l.closeErr = l.closer.Close()
		}
	})
	return l.closeErr
}

func openRotator(f config.LoggingFileConfig) (*timberjack.Logger, error) {
	if f.Path == "" {
		return nil, errors.New("logging: file output requires logging.file.path")
	}
	// timberjack opens lazily on first write; probe now so bad paths fail at startup.
	// Only a file created here gets its mode set; a pre-existing file keeps its
	// mode, which may be owned by someone else (logrotate, ansible, root).
	_, statErr := os.Stat(f.Path)
	created := os.IsNotExist(statErr)
	probe, err := os.OpenFile(f.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("logging: open log file: %w", err)
	}
	if created {
		// Chmod makes the mode exact regardless of umask. A failure is ignored:
		// the file is open and writable, so logging still works.
		_ = probe.Chmod(logFileMode)
	}
	if err := probe.Close(); err != nil {
		return nil, fmt.Errorf("logging: close log file probe: %w", err)
	}

	compress := true
	if f.Compress != nil {
		compress = *f.Compress
	}
	return &timberjack.Logger{
		Filename:   f.Path,
		MaxSize:    f.MaxSizeMB,
		MaxBackups: f.MaxBackups,
		MaxAge:     f.MaxAgeDays,
		Compress:   compress,
		FileMode:   logFileMode,
	}, nil
}
