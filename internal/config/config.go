package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ValidationError carries every problem found in a configuration file. Each
// entry starts with the YAML key path it refers to and never contains secret
// values.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string { return strings.Join(e.Errors, "\n") }

// Warnings returns non-fatal findings collected by Load (open relay networks,
// insecure_skip_verify, unknown log level). The caller decides how to log them.
func (c *Config) Warnings() []string { return append([]string(nil), c.warnings...) }

func (c *Config) warn(msg string) { c.warnings = append(c.warnings, msg) }

func boolPtr(b bool) *bool { return &b }

func defaultPort(tls string) int {
	switch tls {
	case "tls":
		return 465
	case "none":
		return 25
	default:
		return 587
	}
}

// applyDefaults fills unset values. present holds the YAML key paths that
// appeared in the file: timeouts, upstream ports and quota windows are only
// defaulted when their key is absent, so an explicit "0s" or "port: 0" reaches
// validation and is rejected. Other zero values (limits, rotation sizes) still
// mean "unset"; spec 5.3 does not forbid explicit zeros for them.
func (c *Config) applyDefaults(present map[string]bool) error {
	s := &c.Server
	if s.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		s.Hostname = h
	}
	if len(s.Listen) == 0 {
		s.Listen = []ListenConfig{{Address: "127.0.0.1:25", TLS: "none"}}
	}
	for i := range s.Listen {
		if s.Listen[i].TLS == "" {
			s.Listen[i].TLS = "none"
		}
	}
	if s.TLS.Profile == "" {
		s.TLS.Profile = "default"
	}
	setDur(&s.Timeouts.Read, 60*time.Second, present, "server.timeouts.read")
	setDur(&s.Timeouts.Write, 60*time.Second, present, "server.timeouts.write")
	setDur(&s.Timeouts.Data, 5*time.Minute, present, "server.timeouts.data")
	setDur(&s.Timeouts.Shutdown, 30*time.Second, present, "server.timeouts.shutdown")
	if s.Limits.MaxConnections == 0 {
		s.Limits.MaxConnections = 100
	}
	if s.Limits.MaxMessageSize == 0 {
		s.Limits.MaxMessageSize = 10240000
	}
	if s.Limits.MaxRecipients == 0 {
		s.Limits.MaxRecipients = 100
	}
	if s.Limits.MaxLineLength == 0 {
		s.Limits.MaxLineLength = 1 << 20
	}

	// nil means the key was absent; an explicit empty list is kept (open relay).
	if c.Access.AllowedNetworks == nil {
		c.Access.AllowedNetworks = []string{"127.0.0.0/8", "::1/128"}
	}

	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.TLS == "" {
			u.TLS = "starttls"
		}
		up := fmt.Sprintf("upstreams[%d]", i)
		if u.Port == 0 && !present[up+".port"] {
			u.Port = defaultPort(u.TLS)
		}
		if u.Auth != nil && u.Auth.Mechanism == "" {
			u.Auth.Mechanism = "auto"
		}
		setDur(&u.Timeouts.Connect, 10*time.Second, present, up+".timeouts.connect")
		setDur(&u.Timeouts.Command, 30*time.Second, present, up+".timeouts.command")
		setDur(&u.Timeouts.Data, 2*time.Minute, present, up+".timeouts.data")
		if u.Quota != nil {
			setDur(&u.Quota.Window, 24*time.Hour, present, up+".quota.window")
		}
	}

	l := &c.Logging
	if l.Level == "" {
		l.Level = "info"
	}
	if l.Format == "" {
		l.Format = "text"
	}
	if l.Output == "" {
		l.Output = "stdout"
	}
	f := &l.File
	if f.MaxSizeMB == 0 {
		f.MaxSizeMB = 10
	}
	if f.MaxBackups == 0 {
		f.MaxBackups = 3
	}
	if f.MaxAgeDays == 0 {
		f.MaxAgeDays = 30
	}
	if f.Compress == nil {
		f.Compress = boolPtr(true)
	}

	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9090"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	return nil
}

func setDur(d *time.Duration, def time.Duration, present map[string]bool, path string) {
	if *d == 0 && !present[path] {
		*d = def
	}
}
