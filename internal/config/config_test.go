package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// writeCert writes a self-signed cert/key pair and returns their paths.
func writeCert(t *testing.T, dir, prefix string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPath = writeFile(t, dir, prefix+".crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	keyPath = writeFile(t, dir, prefix+".key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	return certPath, keyPath
}

const minimalUpstream = `
upstreams:
  - name: a
    host: smtp.example.com
`

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	return Load(writeFile(t, t.TempDir(), "config.yaml", yaml))
}

func mustLoad(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := load(t, yaml)
	require.NoError(t, err)
	return cfg
}

func validationErrors(t *testing.T, err error) []string {
	t.Helper()
	var ve *ValidationError
	require.True(t, errors.As(err, &ve), "want *ValidationError, got %T: %v", err, err)
	return ve.Errors
}

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("SES_SMTP_USER", "ses-user")
	t.Setenv("SES_SMTP_PASS", "ses-pass")
	t.Setenv("SMTP2GO_USER", "s2g-user")
	t.Setenv("SMTP2GO_PASS", "s2g-pass")

	// The example points state.file at /var/lib, which may not be writable here.
	src, err := os.ReadFile("../../config.example.yaml")
	require.NoError(t, err)
	dir := t.TempDir()
	content := strings.ReplaceAll(string(src), "/var/lib/smtp-relay/state.json", filepath.Join(dir, "state.json"))
	cfg, err := Load(writeFile(t, dir, "config.yaml", content))
	require.NoError(t, err)

	require.Len(t, cfg.Upstreams, 2)
	assert.Equal(t, "ses-eu", cfg.Upstreams[0].Name)
	assert.Equal(t, "ses-user", cfg.Upstreams[0].Auth.Username)
	assert.Equal(t, "ses-pass", cfg.Upstreams[0].Auth.Password.Reveal())
	assert.Equal(t, 2525, cfg.Upstreams[1].Port)
	assert.Equal(t, "auto", cfg.Upstreams[1].Auth.Mechanism)
	assert.Len(t, cfg.Access.Networks, 2)
	assert.Empty(t, cfg.Warnings())
}

func TestExampleConfigUnsetEnv(t *testing.T) {
	for _, k := range []string{"SES_SMTP_USER", "SES_SMTP_PASS", "SMTP2GO_USER", "SMTP2GO_PASS"} {
		t.Setenv(k, "x")
		require.NoError(t, os.Unsetenv(k))
	}
	_, err := Load("../../config.example.yaml")
	errs := validationErrors(t, err)
	assert.Len(t, errs, 4)
}

func TestDefaults(t *testing.T) {
	cfg := mustLoad(t, minimalUpstream)
	host, _ := os.Hostname()

	assert.Equal(t, host, cfg.Server.Hostname)
	assert.Equal(t, []ListenConfig{{Address: "127.0.0.1:25", TLS: "none"}}, cfg.Server.Listen)
	assert.Equal(t, []string{"127.0.0.0/8", "::1/128"}, cfg.Access.AllowedNetworks)
	require.Len(t, cfg.Access.Networks, 2)
	assert.Equal(t, "127.0.0.0/8", cfg.Access.Networks[0].String())
	assert.Equal(t, "::1/128", cfg.Access.Networks[1].String())
	assert.Equal(t, "default", cfg.Server.TLS.Profile)
	assert.Equal(t, 60*time.Second, cfg.Server.Timeouts.Read)
	assert.Equal(t, 60*time.Second, cfg.Server.Timeouts.Write)
	assert.Equal(t, 5*time.Minute, cfg.Server.Timeouts.Data)
	assert.Equal(t, 30*time.Second, cfg.Server.Timeouts.Shutdown)
	assert.Equal(t, 100, cfg.Server.Limits.MaxConnections)
	assert.Equal(t, int64(10240000), cfg.Server.Limits.MaxMessageSize)
	assert.Equal(t, 100, cfg.Server.Limits.MaxRecipients)
	assert.Equal(t, 1048576, cfg.Server.Limits.MaxLineLength)

	u := cfg.Upstreams[0]
	assert.Equal(t, "starttls", u.TLS)
	assert.Equal(t, 587, u.Port)
	assert.Nil(t, u.Auth)
	assert.Equal(t, 10*time.Second, u.Timeouts.Connect)
	assert.Equal(t, 30*time.Second, u.Timeouts.Command)
	assert.Equal(t, 2*time.Minute, u.Timeouts.Data)

	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "text", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)
	assert.Equal(t, 10, cfg.Logging.File.MaxSizeMB)
	assert.Equal(t, 3, cfg.Logging.File.MaxBackups)
	assert.Equal(t, 30, cfg.Logging.File.MaxAgeDays)
	require.NotNil(t, cfg.Logging.File.Compress)
	assert.True(t, *cfg.Logging.File.Compress)

	assert.False(t, cfg.Metrics.Enabled)
	assert.Equal(t, "127.0.0.1:9090", cfg.Metrics.Listen)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)
	assert.Empty(t, cfg.Warnings())
}

func TestDefaultPortByTLS(t *testing.T) {
	cfg := mustLoad(t, `
upstreams:
  - {name: a, host: h, tls: starttls}
  - {name: b, host: h, tls: tls}
  - {name: c, host: h, tls: none}
  - {name: d, host: h}
  - {name: e, host: h, tls: tls, port: 2465}
`)
	var ports []int
	for _, u := range cfg.Upstreams {
		ports = append(ports, u.Port)
	}
	assert.Equal(t, []int{587, 465, 25, 587, 2465}, ports)
}

func TestExplicitValuesKept(t *testing.T) {
	dir := t.TempDir()
	cfg := mustLoad(t, fmt.Sprintf(`
server:
  hostname: relay.lan
  limits: {max_connections: -1, max_line_length: 4096}
  timeouts: {read: 5s}
upstreams:
  - name: a
    host: h
    tls: none
    auth: {username: u, password: p, mechanism: login, allow_insecure_auth: true}
    quota: {limit: 5}
state: {file: %s}
logging: {level: debug, format: json, output: stderr, file: {compress: false}}
`, filepath.Join(dir, "s.json")))
	assert.Equal(t, "relay.lan", cfg.Server.Hostname)
	assert.Equal(t, -1, cfg.Server.Limits.MaxConnections)
	assert.Equal(t, 4096, cfg.Server.Limits.MaxLineLength)
	assert.Equal(t, 5*time.Second, cfg.Server.Timeouts.Read)
	assert.Equal(t, "login", cfg.Upstreams[0].Auth.Mechanism)
	assert.Equal(t, 24*time.Hour, cfg.Upstreams[0].Quota.Window)
	assert.False(t, *cfg.Logging.File.Compress)
	assert.Equal(t, "json", cfg.Logging.Format)
}

func TestEmptyAllowedNetworksIsKeptAndWarns(t *testing.T) {
	cfg := mustLoad(t, "access: {allowed_networks: []}\n"+minimalUpstream)
	assert.Empty(t, cfg.Access.Networks)
	require.Len(t, cfg.Warnings(), 1)
	assert.Contains(t, cfg.Warnings()[0], "open relay")
}

func TestWarnings(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"any ipv4", "access: {allowed_networks: [0.0.0.0/0]}\n" + minimalUpstream, "access.allowed_networks[0]"},
		{"any ipv6", "access: {allowed_networks: ['::/0']}\n" + minimalUpstream, "access.allowed_networks[0]"},
		{"skip verify", "upstreams: [{name: a, host: h, tls_options: {insecure_skip_verify: true}}]", "upstreams[0].tls_options.insecure_skip_verify"},
		{"bad level", "logging: {level: loud}\n" + minimalUpstream, "logging.level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mustLoad(t, tt.yaml)
			require.Len(t, cfg.Warnings(), 1)
			assert.Contains(t, cfg.Warnings()[0], tt.want)
		})
	}

	t.Run("bad level falls back to info", func(t *testing.T) {
		assert.Equal(t, "info", mustLoad(t, "logging: {level: loud}\n"+minimalUpstream).Logging.Level)
	})
}

func TestValidationRules(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCert(t, dir, "srv")
	clientCert, clientKey := writeCert(t, dir, "cli")
	badPEM := writeFile(t, dir, "bad.pem", "not a pem")
	notADir := writeFile(t, dir, "file", "x")

	tests := []struct {
		name string
		yaml string
		want string // substring of one error, including its key path
	}{
		{"no upstreams", "access: {}", "upstreams: at least one upstream"},
		{"upstream name missing", "upstreams: [{host: h}]", "upstreams[0].name: required"},
		{"upstream name format", "upstreams: [{name: Bad Name, host: h}]", "upstreams[0].name: must match"},
		{"upstream name duplicate", "upstreams: [{name: a, host: h}, {name: a, host: h}]", "upstreams[1].name: duplicate"},
		{"upstream host missing", "upstreams: [{name: a}]", "upstreams[0].host: required"},
		{"port too high", "upstreams: [{name: a, host: h, port: 70000}]", "upstreams[0].port: must be between"},
		{"port negative", "upstreams: [{name: a, host: h, port: -1}]", "upstreams[0].port: must be between"},
		{"upstream tls value", "upstreams: [{name: a, host: h, tls: ssl}]", "upstreams[0].tls: must be"},
		{"cidr invalid", "access: {allowed_networks: [nope]}\n" + minimalUpstream, "access.allowed_networks[0]: invalid CIDR"},
		{"cidr host bits", "access: {allowed_networks: [192.168.1.5/24]}\n" + minimalUpstream, "access.allowed_networks[0]: CIDR \"192.168.1.5/24\" has host bits"},
		{"cidr host bits v6", "access: {allowed_networks: ['fe80::1/64']}\n" + minimalUpstream, "has host bits"},
		{"sender no at", "access: {allowed_senders: [nobody]}\n" + minimalUpstream, "access.allowed_senders[0]: must contain exactly one @"},
		{"sender two at", "access: {allowed_senders: ['a@b@c']}\n" + minimalUpstream, "access.allowed_senders[0]: must contain exactly one @"},
		{"sender crlf", "access: {allowed_senders: [\"a@b\\r\\nX: y\"]}\n" + minimalUpstream, "access.allowed_senders[0]: must not contain CR or LF"},
		{"domain with at", "access: {allowed_sender_domains: ['@example.com']}\n" + minimalUpstream, "access.allowed_sender_domains[0]: must be a non-empty domain without @"},
		{"starttls listener without tls", "server: {listen: [{address: ':587', tls: starttls}]}\n" + minimalUpstream, "server.tls.cert_file: required"},
		{"tls listener without key", fmt.Sprintf("server: {listen: [{address: ':465', tls: tls}], tls: {cert_file: %s}}\n%s", certPath, minimalUpstream), "server.tls.key_file: must be set together"},
		{"tls keypair unloadable", fmt.Sprintf("server: {listen: [{address: ':465', tls: tls}], tls: {cert_file: %s, key_file: %s}}\n%s", certPath, badPEM, minimalUpstream), "server.tls: cannot load key pair"},
		{"listener tls value", "server: {listen: [{address: ':25', tls: ssl}]}\n" + minimalUpstream, "server.listen[0].tls: must be"},
		{"listener address", "server: {listen: [{address: nope}]}\n" + minimalUpstream, "server.listen[0].address: invalid address"},
		{"listener duplicate", "server: {listen: [{address: ':25'}, {address: ':25'}]}\n" + minimalUpstream, "server.listen[1].address: duplicate"},
		{"force_tls on none", "server: {listen: [{address: ':25', tls: none, force_tls: true}]}\n" + minimalUpstream, "server.listen[0].force_tls: is only valid for a starttls"},
		{"force_tls on tls", fmt.Sprintf("server: {listen: [{address: ':465', tls: tls, force_tls: true}], tls: {cert_file: %s, key_file: %s}}\n%s", certPath, keyPath, minimalUpstream), "server.listen[0].force_tls"},
		{"tls profile", "server: {tls: {profile: fancy}}\n" + minimalUpstream, "server.tls.profile: must be"},
		{"server timeout too small", "server: {timeouts: {read: 500ms}}\n" + minimalUpstream, "server.timeouts.read: must be at least 1s"},
		{"server timeout bad format", "server: {timeouts: {read: soon}}\n" + minimalUpstream, "server.timeouts.read"},
		{"server timeout negative", "server: {timeouts: {data: -5s}}\n" + minimalUpstream, "server.timeouts.data: must be at least 1s"},
		{"upstream timeout too small", "upstreams: [{name: a, host: h, timeouts: {connect: 999ms}}]", "upstreams[0].timeouts.connect: must be at least 1s"},
		{"max_connections invalid", "server: {limits: {max_connections: -2}}\n" + minimalUpstream, "server.limits.max_connections"},
		{"max_line_length below RFC minimum", "server: {limits: {max_line_length: 999}}\n" + minimalUpstream, "server.limits.max_line_length: must be at least 1000, got 999"},
		{"max_line_length negative", "server: {limits: {max_line_length: -1}}\n" + minimalUpstream, "server.limits.max_line_length: must be at least 1000"},
		{"client cert without key", fmt.Sprintf("upstreams: [{name: a, host: h, tls_options: {client_cert_file: %s}}]", clientCert), "upstreams[0].tls_options.client_key_file: must be set together"},
		{"client key without cert", fmt.Sprintf("upstreams: [{name: a, host: h, tls_options: {client_key_file: %s}}]", clientKey), "upstreams[0].tls_options.client_cert_file: must be set together"},
		{"client keypair unreadable", "upstreams: [{name: a, host: h, tls_options: {client_cert_file: /no/cert, client_key_file: /no/key}}]", "upstreams[0].tls_options: cannot load key pair"},
		{"ca_file unreadable", "upstreams: [{name: a, host: h, tls_options: {ca_file: /no/ca.pem}}]", "upstreams[0].tls_options.ca_file: cannot read"},
		{"ca_file not pem", fmt.Sprintf("upstreams: [{name: a, host: h, tls_options: {ca_file: %s}}]", badPEM), "upstreams[0].tls_options.ca_file: no valid PEM"},
		{"auth with tls none", "upstreams: [{name: a, host: h, tls: none, auth: {username: u, password: p}}]", "upstreams[0].auth: credentials would be sent unencrypted"},
		{"auth mechanism", "upstreams: [{name: a, host: h, auth: {mechanism: ntlm}}]", "upstreams[0].auth.mechanism: must be"},
		{"password and password_file", fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password: p, password_file: %s}}]", writeFile(t, dir, "pw", "x")), "upstreams[0].auth.password: set either"},
		{"password_file unreadable", "upstreams: [{name: a, host: h, auth: {username: u, password_file: /no/such}}]", "upstreams[0].auth.password_file: cannot read"},
		{"quota without state file", "upstreams: [{name: a, host: h, quota: {limit: 5}}]", "state.file: required when any upstream has a quota"},
		{"quota limit zero", fmt.Sprintf("upstreams: [{name: a, host: h, quota: {limit: 0}}]\nstate: {file: %s/s.json}", dir), "upstreams[0].quota.limit: must be greater than 0"},
		{"quota limit negative", fmt.Sprintf("upstreams: [{name: a, host: h, quota: {limit: -1}}]\nstate: {file: %s/s.json}", dir), "upstreams[0].quota.limit"},
		{"quota window short", fmt.Sprintf("upstreams: [{name: a, host: h, quota: {limit: 5, window: 30s}}]\nstate: {file: %s/s.json}", dir), "upstreams[0].quota.window: must be at least 1m0s"},
		{"state dir not writable", "upstreams: [{name: a, host: h, quota: {limit: 5}}]\nstate: {file: " + notADir + "/sub/s.json}", "state.file: directory is not writable"},
		{"log format", "logging: {format: xml}\n" + minimalUpstream, "logging.format: must be text or json"},
		{"log output", "logging: {output: syslog}\n" + minimalUpstream, "logging.output: must be stdout, stderr or file"},
		{"log file path missing", "logging: {output: file}\n" + minimalUpstream, "logging.file.path: required when output is file"},
		{"log file dir not writable", "logging: {output: file, file: {path: " + notADir + "/sub/x.log}}\n" + minimalUpstream, "logging.file.path: directory is not writable"},
		{"metrics listen", "metrics: {listen: nope}\n" + minimalUpstream, "metrics.listen: invalid address"},
		{"metrics path", "metrics: {path: metrics}\n" + minimalUpstream, "metrics.path: must start with /"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			errs := validationErrors(t, err)
			assert.True(t, anyContains(errs, tt.want), "want %q in %q", tt.want, errs)
		})
	}
}

func anyContains(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func TestPasswordAndPasswordFileTogether(t *testing.T) {
	pw := writeFile(t, t.TempDir(), "pw", "file-secret")
	_, err := load(t, fmt.Sprintf(`
upstreams:
  - {name: a, host: h}
  - name: b
    host: h
    auth: {username: u, password: inline-secret, password_file: %s}
`, pw))
	errs := validationErrors(t, err)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "upstreams[1].auth.password:")
	assert.NotContains(t, err.Error(), "inline-secret")
	assert.NotContains(t, err.Error(), "file-secret")
}

func TestPasswordFile(t *testing.T) {
	tests := []struct{ name, content, want string }{
		{"trailing newline", "s3cret\n", "s3cret"},
		{"trailing crlf", "s3cret\r\n", "s3cret"},
		{"no newline", "s3cret", "s3cret"},
		{"inner spaces kept", " a b \n", " a b "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pw := writeFile(t, dir, "pw", tt.content)
			cfg := mustLoad(t, fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password_file: %s}}]", pw))
			assert.Equal(t, tt.want, cfg.Upstreams[0].Auth.Password.Reveal())
		})
	}
}

func TestMultipleErrorsReportedTogether(t *testing.T) {
	_, err := load(t, `
access:
  allowed_networks: [192.168.1.5/24]
  allowed_senders: [bad]
upstreams:
  - {name: a, host: h}
  - {name: a, host: h, port: 99999, tls: none, auth: {username: u, password: p}}
logging: {format: xml}
`)
	errs := validationErrors(t, err)
	for _, want := range []string{
		"access.allowed_networks[0]:",
		"access.allowed_senders[0]:",
		"upstreams[1].name:",
		"upstreams[1].port:",
		"upstreams[1].auth:",
		"logging.format:",
	} {
		assert.True(t, anyContains(errs, want), "missing %q in %q", want, errs)
	}
	assert.Equal(t, strings.Join(errs, "\n"), err.Error())
	assert.Len(t, strings.Split(err.Error(), "\n"), len(errs))
}

func TestUnknownKeys(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"top level", "bogus: 1\n" + minimalUpstream, "bogus: unknown key"},
		{"nested", "server: {lisnten: []}\n" + minimalUpstream, "server.lisnten: unknown key"},
		{"in list", "upstreams: [{name: a, host: h, hots: x}]", "upstreams[0].hots: unknown key"},
		{"old key", "access: {allowed_sender_pattern: '.*'}\n" + minimalUpstream, "access.allowed_sender_pattern: unknown key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.True(t, anyContains(validationErrors(t, err), tt.want), "got %v", err)
		})
	}
}

func TestWrongTypeReportsPath(t *testing.T) {
	_, err := load(t, "upstreams:\n  - name: a\n    host: h\n    port: abc\n")
	require.Error(t, err)
	assert.True(t, anyContains(validationErrors(t, err), "upstreams[0].port:"), "got %v", err)
}

func TestEnvExpansion(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		t.Setenv("RELAY_HOST", "smtp.example.net")
		t.Setenv("RELAY_PORT", "2525")
		t.Setenv("RELAY_PASS", "p: #weird 'value\"")
		cfg := mustLoad(t, `
upstreams:
  - name: a
    host: ${RELAY_HOST}
    port: ${RELAY_PORT}
    auth: {username: "prefix-${RELAY_HOST}", password: "${RELAY_PASS}"}
`)
		u := cfg.Upstreams[0]
		assert.Equal(t, "smtp.example.net", u.Host)
		assert.Equal(t, 2525, u.Port)
		assert.Equal(t, "prefix-smtp.example.net", u.Auth.Username)
		assert.Equal(t, "p: #weird 'value\"", u.Auth.Password.Reveal())
	})

	t.Run("unset names the variable", func(t *testing.T) {
		t.Setenv("MISSING_ONE", "x")
		require.NoError(t, os.Unsetenv("MISSING_ONE"))
		_, err := load(t, "upstreams:\n  - name: a\n    host: ${MISSING_ONE}\n")
		errs := validationErrors(t, err)
		require.Len(t, errs, 1)
		assert.Equal(t, "upstreams[0].host: environment variable MISSING_ONE is not set", errs[0])
	})

	t.Run("set but empty is allowed", func(t *testing.T) {
		t.Setenv("EMPTY_ONE", "")
		cfg := mustLoad(t, "server: {welcome_message: '${EMPTY_ONE}'}\n"+minimalUpstream)
		assert.Empty(t, cfg.Server.WelcomeMessage)
	})

	t.Run("bare dollar untouched", func(t *testing.T) {
		t.Setenv("HOME_X", "should-not-appear")
		cfg := mustLoad(t, `
server: {welcome_message: "cost $HOME_X and $5 and ${ unclosed"}
upstreams:
  - name: a
    host: h
    auth: {username: u, password: "pa$$word$HOME_X"}
`)
		assert.Equal(t, "cost $HOME_X and $5 and ${ unclosed", cfg.Server.WelcomeMessage)
		assert.Equal(t, "pa$$word$HOME_X", cfg.Upstreams[0].Auth.Password.Reveal())
	})

	t.Run("expansion is not re-expanded", func(t *testing.T) {
		t.Setenv("OUTER", "${INNER}")
		cfg := mustLoad(t, "server: {welcome_message: '${OUTER}'}\n"+minimalUpstream)
		assert.Equal(t, "${INNER}", cfg.Server.WelcomeMessage)
	})

	t.Run("comments are ignored", func(t *testing.T) {
		cfg := mustLoad(t, "# uses ${NOT_SET_IN_COMMENT}\n"+minimalUpstream)
		assert.NotNil(t, cfg)
	})
}

func TestLoadFileProblems(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)

	_, err = load(t, "upstreams: [unclosed")
	require.Error(t, err)

	cfg, err := load(t, "")
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Nil(t, cfg)
	assert.True(t, anyContains(ve.Errors, "upstreams: at least one upstream"))
}

func TestSecretNeverLeaks(t *testing.T) {
	const secret = "hunter2-very-secret"
	cfg := mustLoad(t, fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password: %s}}]", secret))
	require.Equal(t, secret, cfg.Upstreams[0].Auth.Password.Reveal())

	// %s is not checked: fmt disables String() methods inside its bad-verb output.
	for _, v := range []any{cfg, *cfg, cfg.Upstreams, cfg.Upstreams[0].Auth, *cfg.Upstreams[0].Auth} {
		out := fmt.Sprintf("%v %+v %#v", v, v, v)
		assert.NotContains(t, out, secret)
	}
	assert.NotContains(t, fmt.Sprintf("%s %v", cfg.Upstreams[0].Auth.Password, cfg.Upstreams[0].Auth.Password), secret)
	b, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.NotContains(t, string(b), secret)
	assert.Contains(t, string(b), "***")
}

func TestErrorPathsInFlowStyle(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
		not  string
	}{
		{"unknown key not last, level 2",
			"access: {allowed_networks: [10.0.0.0/8], bogus: 1, allowed_senders: [x@y]}\n" + minimalUpstream,
			"access.bogus: unknown key", "allowed_senders[0]: unknown"},
		{"unknown key before nested map",
			"upstreams: [{name: a, host: h, hots: [1,2], timeouts: {connect: 0s}}]",
			"upstreams[0].hots: unknown key", "timeouts.connect: unknown"},
		{"unknown key at level 4",
			"upstreams: [{name: a, host: h, auth: {username: u, pasword: p, password: q}}]",
			"upstreams[0].auth.pasword: unknown key", ""},
		{"unknown key at top level on a one-line doc",
			"{upstreams: [{name: a, host: h}], bogus: 1, logging: {level: info}}",
			"bogus: unknown key", "logging"},
		{"two unknown keys on one line",
			"server: {aaa: 1, limits: {max_recipients: 5, zzz: 2}, bbb: 3}\n" + minimalUpstream,
			"server.limits.zzz: unknown key", ""},
		{"type error not last on line",
			"upstreams: [{name: a, host: h, port: abc, tls: starttls}]",
			"upstreams[0].port: expected integer, got string", "upstreams[0].tls"},
		{"type error picks the value, not a neighbour",
			"server: {limits: {max_recipients: x, max_connections: 5}}\n" + minimalUpstream,
			"server.limits.max_recipients: expected integer, got string", "max_connections"},
		{"bad duration",
			"server: {timeouts: {read: soon, write: 5s}}\n" + minimalUpstream,
			"server.timeouts.read: expected duration such as 30s, got string", "write"},
		{"list where scalar expected",
			"upstreams: [{name: a, host: [x], port: 25}]",
			"upstreams[0].host: expected string, got list", ""},
		{"duplicate key",
			"upstreams: [{name: a, name: b, host: h}]",
			"upstreams[0].name: duplicate key", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			errs := validationErrors(t, err)
			assert.True(t, anyContains(errs, tt.want), "want %q in %q", tt.want, errs)
			if tt.not != "" {
				assert.False(t, anyContains(errs, tt.not), "unexpected %q in %q", tt.not, errs)
			}
		})
	}
}

func TestTypeErrorsNeverEchoValues(t *testing.T) {
	const secret = "hunter2-very-secret"
	t.Setenv("LEAKY", secret)
	for _, y := range []string{
		"upstreams: [{name: a, host: h, port: ${LEAKY}}]",
		"upstreams: [{name: a, host: h, tls_options: {insecure_skip_verify: ${LEAKY}}}]",
		"server: {timeouts: {read: ${LEAKY}}}\n" + minimalUpstream,
		"server: {limits: {max_message_size: \"${LEAKY}\"}}\n" + minimalUpstream,
		"upstreams:\n  - name: a\n    host: h\n    port: ${LEAKY}\n",
		"upstreams:\n  - name: a\n    host: h\n    port: short-secret\n",
	} {
		_, err := load(t, y)
		require.Error(t, err, y)
		assert.NotContains(t, err.Error(), secret)
		assert.NotContains(t, err.Error(), secret[:7])
		assert.NotContains(t, err.Error(), "short-secret")
	}
}

func TestEnvExpansionFlowAndQuoting(t *testing.T) {
	t.Setenv("SMTP2GO_USER", "s2g-user")
	t.Setenv("SMTP2GO_PASS", "s2g-pass")
	t.Setenv("REGION", "eu-west-1")

	t.Run("spec 5.2 flow style, unquoted", func(t *testing.T) {
		cfg := mustLoad(t, `
upstreams:
  - name: smtp2go
    host: mail.smtp2go.com
    port: 2525
    auth: { username: ${SMTP2GO_USER}, password: ${SMTP2GO_PASS} }
`)
		a := cfg.Upstreams[0].Auth
		assert.Equal(t, "s2g-user", a.Username)
		assert.Equal(t, "s2g-pass", a.Password.Reveal())
	})

	t.Run("block style", func(t *testing.T) {
		cfg := mustLoad(t, "upstreams:\n  - name: a\n    host: h\n    auth:\n      username: ${SMTP2GO_USER}\n      password: ${SMTP2GO_PASS}\n")
		assert.Equal(t, "s2g-pass", cfg.Upstreams[0].Auth.Password.Reveal())
	})

	t.Run("quoted", func(t *testing.T) {
		cfg := mustLoad(t, `
upstreams:
  - name: a
    host: "${REGION}.double"
    auth: {username: '${SMTP2GO_USER}', password: "${SMTP2GO_PASS}"}
`)
		u := cfg.Upstreams[0]
		assert.Equal(t, "eu-west-1.double", u.Host)
		assert.Equal(t, "s2g-user", u.Auth.Username)
		assert.Equal(t, "s2g-pass", u.Auth.Password.Reveal())
	})

	t.Run("embedded in a longer string, flow and block", func(t *testing.T) {
		cfg := mustLoad(t, "upstreams:\n  - {name: a, host: smtp.${REGION}.example.com}\n  - name: b\n    host: smtp.${REGION}.example.com\n")
		assert.Equal(t, "smtp.eu-west-1.example.com", cfg.Upstreams[0].Host)
		assert.Equal(t, "smtp.eu-west-1.example.com", cfg.Upstreams[1].Host)
	})

	t.Run("two references in one scalar", func(t *testing.T) {
		cfg := mustLoad(t, "server: {welcome_message: ${REGION}-${SMTP2GO_USER}}\n"+minimalUpstream)
		assert.Equal(t, "eu-west-1-s2g-user", cfg.Server.WelcomeMessage)
	})

	t.Run("unset in flow style names the variable only", func(t *testing.T) {
		t.Setenv("GONE", "x")
		require.NoError(t, os.Unsetenv("GONE"))
		_, err := load(t, "upstreams:\n  - {name: a, host: h, auth: {username: ${GONE}, password: p}}\n")
		errs := validationErrors(t, err)
		require.Len(t, errs, 1)
		assert.Equal(t, "upstreams[0].auth.username: environment variable GONE is not set", errs[0])
	})

	t.Run("not expanded in keys or comments", func(t *testing.T) {
		_, err := load(t, "# ${NOT_SET_COMMENT}\nupstreams: [{name: a, host: h}] # ${NOT_SET_TRAILING}\n${KEY_VAR}: 1\n")
		errs := validationErrors(t, err)
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0], "unknown key")
	})
}

func TestEnvValuesStayPlainStrings(t *testing.T) {
	tests := []struct{ name, value string }{
		{"colon and hash", `p@ss: "x" #y`},
		{"newline", "line1\nline2: x"},
		{"null", "null"},
		{"true", "true"},
		{"number", "12345"},
		{"flow map", "{a: b}"},
		{"flow list", "[a, b]"},
		{"anchor and tag", "&a !!int 5"},
		{"quotes", `it's "quoted"`},
		{"dollar refs", "${OTHER} $OTHER"},
		{"sentinel look-alike", "__SMTPRELAY_ENV_0__"},
		{"sentinel look-alike 2", "__SMTPRELAY_ENV_1__ and __SMTPRELAY_ENV_0__"},
		{"leading dash", "- item"},
		{"document marker", "---\nfoo: bar"},
	}
	for _, tt := range tests {
		for _, form := range []string{
			"upstreams: [{name: a, host: h, auth: {username: u, password: %s}}]",
			"upstreams: [{name: a, host: h, auth: {username: u, password: '%s'}}]",
			"upstreams:\n  - name: a\n    host: h\n    auth:\n      username: u\n      password: %s\n",
			"upstreams:\n  - name: a\n    host: h\n    auth:\n      username: u\n      password: \"%s\"\n",
		} {
			t.Run(tt.name, func(t *testing.T) {
				t.Setenv("OTHER", "other-value")
				t.Setenv("VAL", tt.value)
				y := fmt.Sprintf(form, "${VAL}")
				cfg, err := load(t, y)
				require.NoError(t, err, y)
				require.Len(t, cfg.Upstreams, 1)
				assert.Equal(t, tt.value, cfg.Upstreams[0].Auth.Password.Reveal())
				assert.Equal(t, "u", cfg.Upstreams[0].Auth.Username)
				assert.Equal(t, "h", cfg.Upstreams[0].Host)
			})
		}
	}
}

func TestEnvUnsetErrorNeverContainsOtherValues(t *testing.T) {
	const secret = "top-secret-value"
	t.Setenv("HAVE", secret)
	t.Setenv("MISSING_X", "x")
	require.NoError(t, os.Unsetenv("MISSING_X"))
	_, err := load(t, "upstreams: [{name: a, host: h, auth: {username: ${HAVE}, password: ${MISSING_X}}}]")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "MISSING_X")
}

func TestExplicitZeroValuesRejected(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"server read 0s", "server: {timeouts: {read: 0s}}\n" + minimalUpstream, "server.timeouts.read: must be at least 1s"},
		{"server shutdown 0", "server: {timeouts: {shutdown: 0s}}\n" + minimalUpstream, "server.timeouts.shutdown: must be at least 1s"},
		{"upstream connect 0s", "upstreams: [{name: a, host: h, timeouts: {connect: 0s}}]", "upstreams[0].timeouts.connect: must be at least 1s"},
		{"upstream port 0", "upstreams: [{name: a, host: h, port: 0}]", "upstreams[0].port: must be between"},
		{"quota window 0s", "upstreams: [{name: a, host: h, quota: {limit: 5, window: 0s}}]\nstate: {file: /tmp/x/s.json}", "upstreams[0].quota.window: must be at least 1m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.True(t, anyContains(validationErrors(t, err), tt.want), "got %v", err)
		})
	}
}

func TestAuthRules(t *testing.T) {
	dir := t.TempDir()
	empty := writeFile(t, dir, "empty", "\n")
	tests := []struct{ name, yaml, want string }{
		{"empty username", "upstreams: [{name: a, host: h, auth: {username: '', password: p}}]", "upstreams[0].auth.username: required"},
		{"no username key", "upstreams: [{name: a, host: h, auth: {password: p}}]", "upstreams[0].auth.username: required"},
		{"no password at all", "upstreams: [{name: a, host: h, auth: {username: u}}]", "upstreams[0].auth.password: required"},
		{"empty password", "upstreams: [{name: a, host: h, auth: {username: u, password: ''}}]", "upstreams[0].auth.password: must not be empty"},
		{"both set, password empty", fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password: '', password_file: %s}}]", empty), "upstreams[0].auth.password: set either"},
		{"empty password_file contents", fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password_file: %s}}]", empty), "upstreams[0].auth.password_file:"},
		{"empty password_file path", "upstreams: [{name: a, host: h, auth: {username: u, password_file: ''}}]", "upstreams[0].auth.password_file: must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.True(t, anyContains(validationErrors(t, err), tt.want), "got %v", err)
		})
	}
}

func TestPasswordFileTrimsOnlyOneNewline(t *testing.T) {
	tests := []struct{ content, want string }{
		{"s\n", "s"},
		{"s\r\n", "s"},
		{"s\n\n", "s\n"},
		{"s\r\n\r\n", "s\r\n"},
		{"s\r", "s\r"},
	}
	for _, tt := range tests {
		pw := writeFile(t, t.TempDir(), "pw", tt.content)
		cfg := mustLoad(t, fmt.Sprintf("upstreams: [{name: a, host: h, auth: {username: u, password_file: %s}}]", pw))
		assert.Equal(t, tt.want, cfg.Upstreams[0].Auth.Password.Reveal(), "content %q", tt.content)
	}
}

func TestSenderDomainAndTLSFileRules(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := writeCert(t, dir, "srv")
	tests := []struct{ name, yaml, want string }{
		{"domain with LF", "access: {allowed_sender_domains: [\"example.com\\nX: y\"]}\n" + minimalUpstream, "access.allowed_sender_domains[0]: must not contain CR or LF"},
		{"domain with CR", "access: {allowed_sender_domains: [\"example.com\\r\"]}\n" + minimalUpstream, "access.allowed_sender_domains[0]: must not contain CR or LF"},
		{"empty domain", "access: {allowed_sender_domains: ['']}\n" + minimalUpstream, "access.allowed_sender_domains[0]: must be a non-empty domain"},
		{"cert without key (starttls)", fmt.Sprintf("server: {listen: [{address: ':587', tls: starttls}], tls: {cert_file: %s}}\n%s", certPath, minimalUpstream), "server.tls.key_file: must be set together with cert_file"},
		{"key without cert", fmt.Sprintf("server: {listen: [{address: ':587', tls: starttls}], tls: {key_file: %s}}\n%s", certPath, minimalUpstream), "server.tls.cert_file: must be set together with key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.True(t, anyContains(validationErrors(t, err), tt.want), "got %v", err)
		})
	}
}

func TestValidationNeverEchoesEnvDerivedValues(t *testing.T) {
	const secret = "S3cr3t-Value-XYZ"
	// Each case also carries an unrelated validation error (under a top-level
	// key the case does not use) to prove errors stay collected. Decode-stage
	// errors (wrong type) are reported before validation, so they are exempt.
	others := []struct{ key, yaml, path string }{
		{"server:", "\nserver: {limits: {max_recipients: -1}}", "server.limits.max_recipients"},
		{"access:", "\naccess: {allowed_senders: [bad]}", "access.allowed_senders[0]"},
	}
	decodeStage := map[string]bool{"connect timeout": true, "upstream port": true, "max connections": true, "tls_options bool": true}
	tests := []struct{ name, yaml string }{
		{"upstream tls", "upstreams: [{name: a, host: h, tls: '${S}'}]"},
		{"auth mechanism", "upstreams: [{name: a, host: h, auth: {username: u, password: p, mechanism: ${S}}}]"},
		{"logging format", "upstreams: [{name: a, host: h}]\nlogging: {format: ${S}}"},
		{"logging output", "upstreams: [{name: a, host: h}]\nlogging: {output: ${S}}"},
		{"logging level warning", "upstreams: [{name: a, host: h}]\nlogging: {level: ${S}}"},
		{"metrics path", "upstreams: [{name: a, host: h}]\nmetrics: {path: ${S}}"},
		{"metrics listen", "upstreams: [{name: a, host: h}]\nmetrics: {listen: ${S}}"},
		{"server tls profile", "upstreams: [{name: a, host: h}]\nserver: {tls: {profile: ${S}}}"},
		{"listen address", "upstreams: [{name: a, host: h}]\nserver: {listen: [{address: ${S}}]}"},
		{"listen tls", "upstreams: [{name: a, host: h}]\nserver: {listen: [{address: ':25', tls: ${S}}]}"},
		{"allowed network", "upstreams: [{name: a, host: h}]\naccess: {allowed_networks: [${S}]}"},
		{"allowed network host bits", "upstreams: [{name: a, host: h}]\nS_CIDR_PLACEHOLDER"},
		{"allowed sender", "upstreams: [{name: a, host: h}]\naccess: {allowed_senders: [${S}]}"},
		{"allowed sender domain", "upstreams: [{name: a, host: h}]\naccess: {allowed_sender_domains: ['@${S}']}"},
		{"upstream name", "upstreams: [{name: '${S}', host: h}]"},
		{"upstream host (valid, other error present)", "upstreams: [{name: a, host: ${S}}]"},
		{"ca_file", "upstreams: [{name: a, host: h, tls_options: {ca_file: ${S}}}]"},
		{"client cert", "upstreams: [{name: a, host: h, tls_options: {client_cert_file: ${S}, client_key_file: ${S}}}]"},
		{"password_file", "upstreams: [{name: a, host: h, auth: {username: u, password_file: ${S}}}]"},
		{"state file", "upstreams: [{name: a, host: h, quota: {limit: 1}}]\nstate: {file: '${S}/sub/s.json'}"},
		{"log file path", "upstreams: [{name: a, host: h}]\nlogging: {output: file, file: {path: '${S}/sub/x.log'}}"},
		{"connect timeout", "upstreams: [{name: a, host: h, timeouts: {connect: ${S}}}]"},
		{"upstream port", "upstreams: [{name: a, host: h, port: ${S}}]"},
		{"max connections", "upstreams: [{name: a, host: h}]\nserver: {limits: {max_connections: ${S}}}"},
		{"tls_options bool", "upstreams: [{name: a, host: h, tls_options: {insecure_skip_verify: ${S}}}]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("S", secret)
			y := tt.yaml
			if strings.Contains(y, "S_CIDR_PLACEHOLDER") {
				t.Setenv("S", "10.1.2.3/8")
				y = strings.ReplaceAll(y, "S_CIDR_PLACEHOLDER", "access: {allowed_networks: [${S}]}")
			}
			wantPath := ""
			for _, o := range others {
				if !strings.Contains(y, o.key) {
					y += o.yaml
					wantPath = o.path
					break
				}
			}
			_, err := load(t, y)
			require.Error(t, err)
			all := err.Error()
			for _, bad := range []string{secret, "S3c", "10.1.2.3"} {
				assert.NotContains(t, all, bad)
			}
			if !decodeStage[tt.name] {
				assert.Contains(t, all, wantPath, "unrelated error must still be reported")
			}
		})
	}
}

func TestValidationWarningsNeverEchoEnvDerivedValues(t *testing.T) {
	const secret = "S3cr3t-Value-XYZ"
	t.Setenv("S", secret)
	cfg, err := load(t, "upstreams: [{name: a, host: h}]\nlogging: {level: '${S}'}")
	require.NoError(t, err)
	require.Len(t, cfg.Warnings(), 1)
	assert.NotContains(t, cfg.Warnings()[0], "S3c")
	assert.Contains(t, cfg.Warnings()[0], "logging.level")
}

func TestLiteralBadValuesStayHelpful(t *testing.T) {
	tests := []struct{ yaml, want string }{
		{"upstreams: [{name: a, host: h, tls: ssl}]", `upstreams[0].tls: must be starttls, tls or none, got "ssl"`},
		{"upstreams: [{name: a, host: h}]\nlogging: {format: xml}", `logging.format: must be text or json, got "xml"`},
		{"upstreams: [{name: a, host: h}]\nmetrics: {path: m}", `metrics.path: must start with /, got "m"`},
		{"upstreams: [{name: a, host: h}]\naccess: {allowed_networks: [nope]}", `invalid CIDR, got "nope"`},
		{"upstreams: [{name: a, host: h, port: 70000}]", "upstreams[0].port: must be between 1 and 65535, got 70000"},
		{"upstreams: [{name: a, host: h, auth: {username: u, password: p, mechanism: x}}]", `got "x"`},
	}
	for _, tt := range tests {
		_, err := load(t, tt.yaml)
		require.Error(t, err)
		assert.Contains(t, err.Error(), tt.want)
	}
}

func TestUnknownKeyRepeatedOnOneLine(t *testing.T) {
	tests := []struct{ name, yaml, want, not string }{
		{"host inside auth",
			"upstreams: [{auth: {username: u, password: p, host: 1}, name: a, host: h}]",
			"upstreams[0].auth.host: unknown key", "upstreams[0].host: unknown"},
		{"name inside quota",
			"upstreams: [{quota: {limit: 1, name: x}, name: a, host: h}]",
			"upstreams[0].quota.name: unknown key", "upstreams[0].name: unknown"},
		{"top-level key repeated in nested map",
			"{server: {upstreams: 1}, upstreams: [{name: a, host: h}]}",
			"server.upstreams: unknown key", "\nupstreams: unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, err.Error(), tt.not)
		})
	}
}

func TestValidationNeverEchoesEnvValuesViaAliasesAndMerges(t *testing.T) {
	const secret = "S3cr3t-Value-XYZ"
	tests := []struct{ name, secretValue, yaml, wantPath string }{
		{"tls alias in listen and upstream", secret, `
server:
  listen:
    - {address: ':25', tls: &a '${S}'}
    - {address: ':26', tls: *a}
upstreams:
  - {name: a, host: h, tls: *a}
`, "upstreams[0].tls:"},
		{"tls alias between upstreams", secret, `
upstreams:
  - {name: a, host: h, tls: &t ${S}}
  - {name: b, host: h, tls: *t}
`, "upstreams[1].tls:"},
		{"ca_file via alias", secret, `
upstreams:
  - {name: a, host: h, tls_options: {ca_file: &ca '${S}'}}
  - {name: b, host: h, tls_options: {ca_file: *ca}}
`, "upstreams[1].tls_options.ca_file:"},
		{"ca_file via merge key", secret, `
upstreams:
  - {name: a, host: h, tls_options: &opts {ca_file: '${S}'}}
  - {name: b, host: h, tls_options: {<<: *opts}}
`, "upstreams[1].tls_options.ca_file:"},
		{"listen address via alias", secret, `
server:
  listen:
    - {address: &ad '${S}'}
    - {address: *ad}
upstreams: [{name: a, host: h}]
`, "server.listen[1].address:"},
		{"allowed network via alias", secret, `
access:
  allowed_networks: [&n '${S}', *n]
upstreams: [{name: a, host: h}]
`, "access.allowed_networks[1]:"},
		{"allowed network host bits via alias", "10.1.2.3/8", `
access:
  allowed_networks: [&n '${S}', *n]
upstreams: [{name: a, host: h}]
`, "access.allowed_networks[1]:"},
		{"duration via alias (too small)", "500ms", `
upstreams:
  - {name: a, host: h, timeouts: {connect: &d '${S}'}}
  - {name: b, host: h, timeouts: {connect: *d}}
`, "upstreams[1].timeouts.connect:"},
		{"whole upstream via merge key", secret, `
upstreams:
  - &base {name: a, host: h, tls: '${S}'}
  - {<<: *base, name: b}
`, "upstreams[1].tls:"},
		{"merge from a sequence of anchors", secret, `
upstreams:
  - &u1 {name: a, host: h}
  - &u2 {name: b, host: h, tls: '${S}'}
  - {<<: [*u1, *u2], name: c}
`, "upstreams[2].tls:"},
		{"alias to a mapping holding the secret", secret, `
upstreams:
  - {name: a, host: h, tls_options: &o {ca_file: '${S}'}}
  - {name: b, host: h, tls_options: *o}
`, "upstreams[1].tls_options.ca_file:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("S", tt.secretValue)
			_, err := load(t, tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantPath, "the aliased location must be reported")
			for _, bad := range []string{secret, "S3c", "10.1.2.3", "500ms"} {
				assert.NotContains(t, err.Error(), bad)
			}
		})
	}

	t.Run("warning through alias", func(t *testing.T) {
		t.Setenv("S", "0.0.0.0/0")
		cfg := mustLoad(t, "access: {allowed_networks: [&n '${S}', *n]}\n"+minimalUpstream)
		require.NotEmpty(t, cfg.Warnings())
		for _, w := range cfg.Warnings() {
			assert.NotContains(t, w, "0.0.0.0")
		}
	})
}

func TestAliasedLiteralValuesStayHelpful(t *testing.T) {
	_, err := load(t, `
upstreams:
  - {name: a, host: h, tls: &t ssl}
  - {name: b, host: h, tls: *t}
`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `upstreams[0].tls: must be starttls, tls or none, got "ssl"`)
	assert.Contains(t, err.Error(), `upstreams[1].tls: must be starttls, tls or none, got "ssl"`)
}

func TestMergeKeysCountAsPresent(t *testing.T) {
	t.Run("explicit zero timeout via merge is rejected", func(t *testing.T) {
		_, err := load(t, `
upstreams:
  - {name: a, host: h, timeouts: &d {connect: 0s}}
  - {name: b, host: h, timeouts: {<<: *d}}
`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "upstreams[1].timeouts.connect: must be at least 1s")
	})

	t.Run("explicit zero upstream port via merge is rejected", func(t *testing.T) {
		_, err := load(t, `
upstreams:
  - &b {name: a, host: h, port: 0}
  - {<<: *b, name: b}
`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "upstreams[1].port: must be between")
	})

	t.Run("password via merge plus password_file is both set", func(t *testing.T) {
		pw := writeFile(t, t.TempDir(), "pw", "x")
		_, err := load(t, fmt.Sprintf(`
upstreams:
  - {name: a, host: h, auth: &auth {username: u, password: p}}
  - name: b
    host: h
    auth:
      <<: *auth
      password_file: %s
`, pw))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "upstreams[1].auth.password: set either")
	})

	t.Run("merged password alone is accepted", func(t *testing.T) {
		cfg := mustLoad(t, `
upstreams:
  - {name: a, host: h, auth: &auth {username: u, password: p}}
  - {name: b, host: h, auth: {<<: *auth}}
`)
		assert.Equal(t, "p", cfg.Upstreams[1].Auth.Password.Reveal())
	})

	t.Run("local key overrides merged key", func(t *testing.T) {
		cfg := mustLoad(t, `
upstreams:
  - {name: a, host: h, timeouts: &d {connect: 10s, command: 20s}}
  - {name: b, host: h, timeouts: {<<: *d, connect: 5s}}
`)
		assert.Equal(t, 5*time.Second, cfg.Upstreams[1].Timeouts.Connect)
		assert.Equal(t, 20*time.Second, cfg.Upstreams[1].Timeouts.Command)
	})
}

func TestAliasBombIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("access:\n  allowed_senders:\n  - &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 12; i++ {
		fmt.Fprintf(&b, "  - &a%d [", i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	b.WriteString("upstreams: [{name: a, host: h}]\n")

	start := time.Now()
	_, err := load(t, b.String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alias")
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestMergeBombIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("upstreams:\n  - &m0 {name: a, host: h}\n")
	for i := 1; i < 40; i++ {
		fmt.Fprintf(&b, "  - &m%d {<<: [*m%d, *m%d], name: n%d}\n", i, i-1, i-1, i)
	}

	start := time.Now()
	_, err := load(t, b.String())
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestMaxLineLengthBoundaryAndZeroFallsBack(t *testing.T) {
	assert.Equal(t, 1000, mustLoad(t, "server: {limits: {max_line_length: 1000}}\n"+minimalUpstream).Server.Limits.MaxLineLength)
	// Like the other limits.* keys, an explicit 0 means "use the default".
	assert.Equal(t, 1048576, mustLoad(t, "server: {limits: {max_line_length: 0}}\n"+minimalUpstream).Server.Limits.MaxLineLength)
}
