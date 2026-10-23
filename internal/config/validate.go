package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var upstreamName = regexp.MustCompile(`^[a-z0-9_-]+$`)

type validator struct {
	cfg      *Config
	present  map[string]bool
	expanded map[string]bool
	errs     []string
}

func (v *validator) errf(path, format string, args ...any) {
	v.errs = append(v.errs, path+": "+fmt.Sprintf(format, args...))
}

const hidden = "<value from environment, not shown>"

// q quotes a configured value for a message, unless the value at path came from
// a ${VAR} substitution: a secret placed in the wrong field must not be echoed.
func (v *validator) q(path string, val any) string {
	if v.expanded[path] {
		return hidden
	}
	if s, ok := val.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprint(val)
}

// got renders ", got <value>" for validation messages, or a note that the
// value is hidden when it came from the environment.
func (v *validator) got(path string, val any) string {
	if v.expanded[path] {
		return " (" + hidden + ")"
	}
	return ", got " + v.q(path, val)
}

// detail appends err's text unless any of the given paths is env-derived,
// because OS errors often contain the file path that was tried.
func (v *validator) detail(err error, paths ...string) string {
	for _, p := range paths {
		if v.expanded[p] {
			return ""
		}
	}
	return ": " + err.Error()
}

// validate checks the defaulted config, resolves *_file secrets, parses CIDRs
// and records warnings. It returns a *ValidationError holding every problem.
func (c *Config) validate(present, expanded map[string]bool) error {
	v := &validator{cfg: c, present: present, expanded: expanded}
	v.server()
	v.access()
	v.upstreams()
	v.state()
	v.logging()
	v.metrics()
	if len(v.errs) > 0 {
		return &ValidationError{Errors: v.errs}
	}
	return nil
}

func oneOf(s string, allowed ...string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

func hasCRLF(s string) bool { return strings.ContainsAny(s, "\r\n") }

func (v *validator) minDuration(path string, d, min time.Duration) {
	if d < min {
		v.errf(path, "must be at least %s%s", min, v.got(path, d))
	}
}

func (v *validator) server() {
	s := &v.cfg.Server
	if hasCRLF(s.Hostname) || strings.ContainsAny(s.Hostname, " \t") {
		v.errf("server.hostname", "must not contain whitespace")
	}
	if hasCRLF(s.WelcomeMessage) {
		v.errf("server.welcome_message", "must not contain CR or LF")
	}

	needTLS := false
	seen := map[string]bool{}
	for i, l := range s.Listen {
		p := fmt.Sprintf("server.listen[%d]", i)
		if reason := checkHostPort(l.Address); reason != "" {
			v.errf(p+".address", "%s%s", reason, v.got(p+".address", l.Address))
		} else if seen[l.Address] {
			v.errf(p+".address", "duplicate listen address %s", v.q(p+".address", l.Address))
		}
		seen[l.Address] = true
		if !oneOf(l.TLS, "none", "starttls", "tls") {
			v.errf(p+".tls", "must be none, starttls or tls%s", v.got(p+".tls", l.TLS))
		}
		if l.TLS == "starttls" || l.TLS == "tls" {
			needTLS = true
		}
		if l.ForceTLS && l.TLS != "starttls" {
			v.errf(p+".force_tls", "is only valid for a starttls listener")
		}
	}

	if !oneOf(s.TLS.Profile, "default", "modern", "intermediate", "legacy") {
		v.errf("server.tls.profile", "must be default, modern, intermediate or legacy%s", v.got("server.tls.profile", s.TLS.Profile))
	}
	if needTLS {
		v.keyPair("server.tls", "cert_file", s.TLS.CertFile, "key_file", s.TLS.KeyFile, true)
	}

	v.minDuration("server.timeouts.read", s.Timeouts.Read, time.Second)
	v.minDuration("server.timeouts.write", s.Timeouts.Write, time.Second)
	v.minDuration("server.timeouts.data", s.Timeouts.Data, time.Second)
	v.minDuration("server.timeouts.shutdown", s.Timeouts.Shutdown, time.Second)

	if s.Limits.MaxConnections < -1 {
		v.errf("server.limits.max_connections", "must be -1 (unlimited) or positive%s", v.got("server.limits.max_connections", s.Limits.MaxConnections))
	}
	if s.Limits.MaxMessageSize < 0 {
		v.errf("server.limits.max_message_size", "must be positive%s", v.got("server.limits.max_message_size", s.Limits.MaxMessageSize))
	}
	if s.Limits.MaxRecipients < 0 {
		v.errf("server.limits.max_recipients", "must be positive%s", v.got("server.limits.max_recipients", s.Limits.MaxRecipients))
	}
}

// keyPair checks a cert/key pair. When required is false, setting neither is fine.
func (v *validator) keyPair(path, certKey, cert, keyKey, key string, required bool) {
	switch {
	case cert == "" && key == "":
		if required {
			v.errf(path+"."+certKey, "required when a listener uses starttls or tls")
			v.errf(path+"."+keyKey, "required when a listener uses starttls or tls")
		}
	case cert == "":
		v.errf(path+"."+certKey, "must be set together with %s", keyKey)
	case key == "":
		v.errf(path+"."+keyKey, "must be set together with %s", certKey)
	default:
		if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
			v.errf(path, "cannot load key pair (%s, %s)%s", certKey, keyKey, v.detail(err, path+"."+certKey, path+"."+keyKey))
		}
	}
}

// checkHostPort returns "" for a valid host:port, otherwise a reason that
// does not contain the address (it may be env-derived).
func checkHostPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "invalid address, want host:port"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "invalid address, port must be between 0 and 65535"
	}
	return ""
}

func (v *validator) access() {
	a := &v.cfg.Access
	a.Networks = nil
	for i, s := range a.AllowedNetworks {
		p := fmt.Sprintf("access.allowed_networks[%d]", i)
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			v.errf(p, "invalid CIDR%s", v.got(p, s))
			continue
		}
		if !ip.Equal(n.IP) {
			if v.expanded[p] {
				v.errf(p, "CIDR has host bits set (%s)", hidden)
			} else {
				v.errf(p, "CIDR %q has host bits set (did you mean %s?)", s, n)
			}
			continue
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			v.cfg.warn(fmt.Sprintf("%s: %s allows every address (open relay)", p, v.q(p, s)))
		}
		a.Networks = append(a.Networks, n)
	}
	if len(a.AllowedNetworks) == 0 {
		v.cfg.warn("access.allowed_networks: empty list, every address is allowed (open relay)")
	}

	for i, s := range a.AllowedSenders {
		p := fmt.Sprintf("access.allowed_senders[%d]", i)
		switch {
		case hasCRLF(s):
			v.errf(p, "must not contain CR or LF")
		case strings.Count(s, "@") != 1:
			v.errf(p, "must contain exactly one @%s", v.got(p, s))
		}
	}
	for i, s := range a.AllowedSenderDomains {
		p := fmt.Sprintf("access.allowed_sender_domains[%d]", i)
		switch {
		case hasCRLF(s):
			v.errf(p, "must not contain CR or LF")
		case s == "" || strings.Contains(s, "@"):
			v.errf(p, "must be a non-empty domain without @%s", v.got(p, s))
		}
	}
}

func (v *validator) upstreams() {
	if len(v.cfg.Upstreams) == 0 {
		v.errf("upstreams", "at least one upstream is required")
		return
	}
	names := map[string]bool{}
	for i := range v.cfg.Upstreams {
		u := &v.cfg.Upstreams[i]
		p := fmt.Sprintf("upstreams[%d]", i)

		switch {
		case u.Name == "":
			v.errf(p+".name", "required")
		case !upstreamName.MatchString(u.Name):
			v.errf(p+".name", "must match [a-z0-9_-]+%s", v.got(p+".name", u.Name))
		case names[u.Name]:
			v.errf(p+".name", "duplicate upstream name %s", v.q(p+".name", u.Name))
		}
		names[u.Name] = true

		if u.Host == "" {
			v.errf(p+".host", "required")
		}
		if u.Port < 1 || u.Port > 65535 { // an explicit "port: 0" is not defaulted, so it lands here
			v.errf(p+".port", "must be between 1 and 65535%s", v.got(p+".port", u.Port))
		}
		if !oneOf(u.TLS, "starttls", "tls", "none") {
			v.errf(p+".tls", "must be starttls, tls or none%s", v.got(p+".tls", u.TLS))
		}

		v.upstreamAuth(p, u)
		v.upstreamTLSOptions(p, u)

		v.minDuration(p+".timeouts.connect", u.Timeouts.Connect, time.Second)
		v.minDuration(p+".timeouts.command", u.Timeouts.Command, time.Second)
		v.minDuration(p+".timeouts.data", u.Timeouts.Data, time.Second)

		if q := u.Quota; q != nil {
			if q.Limit <= 0 {
				v.errf(p+".quota.limit", "must be greater than 0%s", v.got(p+".quota.limit", q.Limit))
			}
			v.minDuration(p+".quota.window", q.Window, time.Minute)
		}
	}
}

func (v *validator) upstreamAuth(p string, u *UpstreamConfig) {
	a := u.Auth
	if a == nil {
		return
	}
	p += ".auth"
	if a.Username == "" {
		v.errf(p+".username", "required when auth is set")
	}
	if !oneOf(a.Mechanism, "auto", "plain", "login") {
		v.errf(p+".mechanism", "must be auto, plain or login%s", v.got(p+".mechanism", a.Mechanism))
	}
	if u.TLS == "none" && !a.AllowInsecureAuth {
		v.errf(p, "credentials would be sent unencrypted with tls: none; use starttls/tls or set allow_insecure_auth: true")
	}

	pw, pwf := v.present[p+".password"], v.present[p+".password_file"]
	switch {
	case pw && pwf:
		v.errf(p+".password", "set either password or password_file, not both")
	case pwf:
		if a.PasswordFile == "" {
			v.errf(p+".password_file", "must not be empty")
			break
		}
		b, err := os.ReadFile(a.PasswordFile)
		if err != nil {
			v.errf(p+".password_file", "cannot read %s%s", v.q(p+".password_file", a.PasswordFile), v.detail(unwrapPathError(err), p+".password_file"))
			break
		}
		a.Password = Secret(trimOneNewline(string(b)))
		if a.Password == "" {
			v.errf(p+".password_file", "%s is empty", v.q(p+".password_file", a.PasswordFile))
		}
	case pw:
		if a.Password == "" {
			v.errf(p+".password", "must not be empty")
		}
	default:
		v.errf(p+".password", "required (or set password_file)")
	}
}

// trimOneNewline strips a single trailing "\n" or "\r\n": editors and
// `echo` add one, but further newlines could be part of the secret.
func trimOneNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

func unwrapPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

func (v *validator) upstreamTLSOptions(p string, u *UpstreamConfig) {
	o := &u.TLSOptions
	p += ".tls_options"
	if o.InsecureSkipVerify {
		v.cfg.warn(p + ".insecure_skip_verify: certificate verification is disabled")
	}
	if o.CAFile != "" {
		b, err := os.ReadFile(o.CAFile)
		switch {
		case err != nil:
			v.errf(p+".ca_file", "cannot read %s%s", v.q(p+".ca_file", o.CAFile), v.detail(unwrapPathError(err), p+".ca_file"))
		case !x509.NewCertPool().AppendCertsFromPEM(b):
			v.errf(p+".ca_file", "no valid PEM certificate found in %s", v.q(p+".ca_file", o.CAFile))
		}
	}
	v.keyPair(p, "client_cert_file", o.ClientCertFile, "client_key_file", o.ClientKeyFile, false)
}

func (v *validator) state() {
	var quotaUpstream bool
	for _, u := range v.cfg.Upstreams {
		if u.Quota != nil {
			quotaUpstream = true
		}
	}
	if !quotaUpstream {
		return
	}
	f := v.cfg.State.File
	if f == "" {
		v.errf("state.file", "required when any upstream has a quota")
		return
	}
	if err := checkDirWritable(filepath.Dir(f)); err != nil {
		v.errf("state.file", "directory is not writable%s", v.detail(err, "state.file"))
	}
}

func (v *validator) logging() {
	l := &v.cfg.Logging
	if !oneOf(l.Level, "trace", "debug", "info", "warn", "error") {
		v.cfg.warn(fmt.Sprintf("logging.level: unknown level %s, using info", v.q("logging.level", l.Level)))
		l.Level = "info"
	}
	if !oneOf(l.Format, "text", "json") {
		v.errf("logging.format", "must be text or json%s", v.got("logging.format", l.Format))
	}
	if !oneOf(l.Output, "stdout", "stderr", "file") {
		v.errf("logging.output", "must be stdout, stderr or file%s", v.got("logging.output", l.Output))
		return
	}
	if l.Output != "file" {
		return
	}
	if l.File.Path == "" {
		v.errf("logging.file.path", "required when output is file")
		return
	}
	if err := checkDirWritable(filepath.Dir(l.File.Path)); err != nil {
		v.errf("logging.file.path", "directory is not writable%s", v.detail(err, "logging.file.path"))
	}
}

func (v *validator) metrics() {
	m := &v.cfg.Metrics
	if reason := checkHostPort(m.Listen); reason != "" {
		v.errf("metrics.listen", "%s%s", reason, v.got("metrics.listen", m.Listen))
	}
	if !strings.HasPrefix(m.Path, "/") {
		v.errf("metrics.path", "must start with /%s", v.got("metrics.path", m.Path))
	}
}

// checkDirWritable verifies dir exists and is writable, or can be created by
// finding the nearest existing ancestor and testing that. It creates nothing
// permanent so -check-config has no side effects.
func checkDirWritable(dir string) error {
	probe := dir
	for {
		st, err := os.Stat(probe)
		if err == nil {
			if !st.IsDir() {
				return fmt.Errorf("%s is not a directory", probe)
			}
			break
		}
		if !os.IsNotExist(err) {
			return unwrapPathError(err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return unwrapPathError(err)
		}
		probe = parent
	}
	f, err := os.CreateTemp(probe, ".smtp-relay-check-*")
	if err != nil {
		return fmt.Errorf("%s: %v", probe, unwrapPathError(err))
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
