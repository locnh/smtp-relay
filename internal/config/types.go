// Package config defines the smtp-relay configuration schema.
//
// This file only declares types. Loading, ${ENV} expansion, defaults and
// validation live in load.go / validate.go.
package config

import (
	"net"
	"time"
)

// Config is the root of the YAML configuration file.
type Config struct {
	Server    ServerConfig     `yaml:"server"`
	Access    AccessConfig     `yaml:"access"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`
	State     StateConfig      `yaml:"state"`
	Logging   LoggingConfig    `yaml:"logging"`
	Metrics   MetricsConfig    `yaml:"metrics"`

	warnings []string
}

// ServerConfig describes the listening side of the relay.
type ServerConfig struct {
	Hostname       string          `yaml:"hostname"`
	WelcomeMessage string          `yaml:"welcome_message"`
	Listen         []ListenConfig  `yaml:"listen"`
	TLS            ServerTLSConfig `yaml:"tls"`
	Timeouts       ServerTimeouts  `yaml:"timeouts"`
	Limits         ServerLimits    `yaml:"limits"`
}

// ListenConfig is one listener. TLS is "none", "starttls" or "tls".
type ListenConfig struct {
	Address  string `yaml:"address"`
	TLS      string `yaml:"tls"`
	ForceTLS bool   `yaml:"force_tls"`
}

// ServerTLSConfig is the certificate used by starttls/tls listeners.
// Profile is "default", "modern", "intermediate" or "legacy".
type ServerTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	Profile  string `yaml:"profile"`
}

// ServerTimeouts are socket timeouts for the listening side.
type ServerTimeouts struct {
	Read     time.Duration `yaml:"read"`
	Write    time.Duration `yaml:"write"`
	Data     time.Duration `yaml:"data"`
	Shutdown time.Duration `yaml:"shutdown"`
}

// ServerLimits bounds resource use. MaxConnections == -1 means unlimited.
type ServerLimits struct {
	MaxConnections int   `yaml:"max_connections"`
	MaxMessageSize int64 `yaml:"max_message_size"`
	MaxRecipients  int   `yaml:"max_recipients"`
}

// AccessConfig is the only access gate (clients are not authenticated).
type AccessConfig struct {
	AllowedNetworks      []string `yaml:"allowed_networks"`
	AllowedSenders       []string `yaml:"allowed_senders"`
	AllowedSenderDomains []string `yaml:"allowed_sender_domains"`

	// Networks is AllowedNetworks parsed into CIDRs. Filled by Load/Validate,
	// never read from YAML.
	Networks []*net.IPNet `yaml:"-"`
}

// UpstreamConfig is one real SMTP server. Position in the list is its priority.
type UpstreamConfig struct {
	Name       string             `yaml:"name"`
	Host       string             `yaml:"host"`
	Port       int                `yaml:"port"`
	TLS        string             `yaml:"tls"` // "starttls", "tls" or "none"
	Auth       *AuthConfig        `yaml:"auth"`
	TLSOptions UpstreamTLSOptions `yaml:"tls_options"`
	Timeouts   UpstreamTimeouts   `yaml:"timeouts"`
	Quota      *QuotaConfig       `yaml:"quota"`
}

// AuthConfig holds the credentials used towards an upstream.
// Mechanism is "auto", "plain" or "login".
type AuthConfig struct {
	Mechanism         string `yaml:"mechanism"`
	Username          string `yaml:"username"`
	Password          Secret `yaml:"password"`
	PasswordFile      string `yaml:"password_file"`
	AllowInsecureAuth bool   `yaml:"allow_insecure_auth"`
}

// UpstreamTLSOptions tunes certificate verification and mutual TLS.
type UpstreamTLSOptions struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
}

// UpstreamTimeouts bound each phase of talking to an upstream.
type UpstreamTimeouts struct {
	Connect time.Duration `yaml:"connect"`
	Command time.Duration `yaml:"command"`
	Data    time.Duration `yaml:"data"`
}

// QuotaConfig is a soft per-upstream message quota (never blocks mail).
type QuotaConfig struct {
	Limit  int64         `yaml:"limit"`
	Window time.Duration `yaml:"window"`
}

// StateConfig locates the file holding quota counters.
type StateConfig struct {
	File string `yaml:"file"`
}

// LoggingConfig selects exactly one output and one format.
type LoggingConfig struct {
	Level  string            `yaml:"level"`  // trace|debug|info|warn|error
	Format string            `yaml:"format"` // text|json
	Output string            `yaml:"output"` // stdout|stderr|file
	File   LoggingFileConfig `yaml:"file"`
}

// LoggingFileConfig applies when Output == "file". Compress is a pointer so an
// unset value can default to true.
type LoggingFileConfig struct {
	Path       string `yaml:"path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   *bool  `yaml:"compress"`
}

// MetricsConfig configures the Prometheus/health HTTP endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}
