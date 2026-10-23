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

	switch cfg.Format {
	case "json":
	case "text":
		out = zerolog.ConsoleWriter{Out: out, NoColor: true, TimeFormat: time.RFC3339}
	default:
		if closer != nil {
			_ = closer.Close()
		}
		return nil, fmt.Errorf("logging: unknown format %q (want text or json)", cfg.Format)
	}

	base := zerolog.New(out).With().Timestamp().Logger()

	lvl, ok := levels[cfg.Level]
	if !ok {
		lvl = zerolog.InfoLevel
	}
	base = base.Level(lvl)
	if !ok {
		base.Warn().Str("configured_level", cfg.Level).Msg("unknown log level, using info")
	}

	return &Logger{logger: base, closer: closer}, nil
}

var levels = map[string]zerolog.Level{
	"trace": zerolog.TraceLevel,
	"debug": zerolog.DebugLevel,
	"info":  zerolog.InfoLevel,
	"warn":  zerolog.WarnLevel,
	"error": zerolog.ErrorLevel,
}

// Zerolog returns a value copy of the underlying logger.
func (l *Logger) Zerolog() zerolog.Logger {
	return l.logger
}

// Close flushes and closes the file rotator. It is a no-op for stdout and
// stderr and safe to call more than once.
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
	probe, err := os.OpenFile(f.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("logging: open log file: %w", err)
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
	}, nil
}
