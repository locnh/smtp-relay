package upstream_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCA is a throwaway certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// issue returns a leaf certificate valid for 127.0.0.1, usable as server and client.
func (ca *testCA) issue(t *testing.T, cn string) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair, certPEM, keyPEM
}

func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// serverOpts scripts the behaviour of the fake SMTP server.
type serverOpts struct {
	TLSConfig  *tls.Config // certificate used for STARTTLS / implicit TLS
	Implicit   bool        // TLS from the first byte
	StartTLS   bool        // advertise STARTTLS
	AuthMechs  string      // e.g. "PLAIN LOGIN"; "" = no AUTH advertised
	User, Pass string      // accepted credentials

	// Fail maps a stage to a complete reply line that replaces the normal one.
	// Stages: EHLO (also answers the HELO fallback), MAIL, RCPT, DATA,
	// AFTERDATA, STARTTLS.
	Fail map[string]string
	// Hang makes the server stop answering at a stage: GREETING, EHLO,
	// STARTTLS, AUTH, MAIL, RCPT, DATA, AFTERDATA.
	Hang string
	// CloseAt drops the connection abruptly at the given stage (same names).
	CloseAt string
	// DataDelay delays the final reply after the message body.
	DataDelay time.Duration
}

// fakeServer is a minimal scripted SMTP server that records everything it sees.
type fakeServer struct {
	t    *testing.T
	opts serverOpts
	ln   net.Listener

	mu         sync.Mutex
	lines      []string // every command line, plus AUTH continuation lines
	raw        bytes.Buffer
	ehlo       []string
	mailFrom   string
	mailParams string // ESMTP parameters after the address, e.g. BODY=8BITMIME
	rcpts      []string
	data       []byte
	delivered  bool
	conns      []net.Conn
	peerCerts  []*x509.Certificate
	tlsErrs    []error
	tlsActive  bool
	connCount  int
	wg         sync.WaitGroup
	closedOnce sync.Once
}

func startServer(t *testing.T, opts serverOpts) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, opts: opts, ln: ln}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.close)
	return s
}

func (s *fakeServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeServer) close() {
	s.closedOnce.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func (s *fakeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.connCount++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c)
		}()
	}
}

// recConn records every byte read from the TCP socket (ciphertext once TLS is on).
type recConn struct {
	net.Conn
	s *fakeServer
}

func (c recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.mu.Lock()
		c.s.raw.Write(p[:n])
		c.s.mu.Unlock()
	}
	return n, err
}

func (s *fakeServer) at(stage string) bool { return s.opts.CloseAt == stage }

// blockUntilClosed swallows input until the peer goes away.
func blockUntilClosed(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

func (s *fakeServer) handle(raw net.Conn) {
	var conn net.Conn = recConn{raw, s}
	tlsOn := false
	if s.opts.Implicit {
		tc := tls.Server(conn, s.opts.TLSConfig)
		if err := tc.Handshake(); err != nil {
			s.mu.Lock()
			s.tlsErrs = append(s.tlsErrs, err)
			s.mu.Unlock()
			return
		}
		s.recordPeer(tc)
		conn, tlsOn = tc, true
	}
	r := bufio.NewReader(conn)
	reply := func(l string) { _, _ = io.WriteString(conn, l+"\r\n") }
	// stop applies HANG/CLOSE scripting; true means the handler must return.
	stop := func(stage string) bool {
		if s.opts.CloseAt == stage {
			return true
		}
		if s.opts.Hang == stage {
			blockUntilClosed(conn)
			return true
		}
		return false
	}
	// failOr sends the scripted failure for a stage or the normal reply.
	failOr := func(stage, ok string) {
		if f, found := s.opts.Fail[stage]; found {
			reply(f)
			return
		}
		reply(ok)
	}

	if stop("GREETING") {
		return
	}
	reply("220 fake.test ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.record(line)
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO "), strings.HasPrefix(verb, "HELO "):
			s.mu.Lock()
			s.ehlo = append(s.ehlo, line[5:])
			s.mu.Unlock()
			if stop("EHLO") {
				return
			}
			if f, found := s.opts.Fail["EHLO"]; found {
				reply(f)
				continue
			}
			reply("250-fake.test")
			reply("250-8BITMIME")
			if s.opts.StartTLS && !tlsOn {
				reply("250-STARTTLS")
			}
			if s.opts.AuthMechs != "" {
				reply("250-AUTH " + s.opts.AuthMechs)
			}
			reply("250 SIZE 10485760")
		case verb == "STARTTLS":
			if stop("STARTTLS") {
				return
			}
			if f, found := s.opts.Fail["STARTTLS"]; found {
				reply(f)
				continue
			}
			reply("220 Ready to start TLS")
			tc := tls.Server(conn, s.opts.TLSConfig)
			if err := tc.Handshake(); err != nil {
				s.mu.Lock()
				s.tlsErrs = append(s.tlsErrs, err)
				s.mu.Unlock()
				return
			}
			s.recordPeer(tc)
			conn, tlsOn = tc, true
			r = bufio.NewReader(conn)
			reply = func(l string) { _, _ = io.WriteString(conn, l+"\r\n") }
		case strings.HasPrefix(verb, "AUTH "):
			if stop("AUTH") {
				return
			}
			if !s.auth(conn, r, line, reply) {
				return
			}
		case strings.HasPrefix(verb, "MAIL FROM:"):
			if stop("MAIL") {
				return
			}
			s.mu.Lock()
			s.mailFrom, s.mailParams = splitAddr(line[len("MAIL FROM:"):])
			s.mu.Unlock()
			failOr("MAIL", "250 OK")
		case strings.HasPrefix(verb, "RCPT TO:"):
			if stop("RCPT") {
				return
			}
			s.mu.Lock()
			rcpt, _ := splitAddr(line[len("RCPT TO:"):])
			s.rcpts = append(s.rcpts, rcpt)
			s.mu.Unlock()
			failOr("RCPT", "250 OK")
		case verb == "DATA":
			if stop("DATA") {
				return
			}
			if f, found := s.opts.Fail["DATA"]; found {
				reply(f)
				continue
			}
			reply("354 End data with <CR><LF>.<CR><LF>")
			body, err := readData(r)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.data = body
			s.mu.Unlock()
			if stop("AFTERDATA") {
				return
			}
			time.Sleep(s.opts.DataDelay)
			if f, found := s.opts.Fail["AFTERDATA"]; found {
				reply(f)
				continue
			}
			s.mu.Lock()
			s.delivered = true
			s.mu.Unlock()
			reply("250 2.0.0 OK queued")
		case verb == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 OK")
		}
	}
}

func (s *fakeServer) recordPeer(tc *tls.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsActive = true
	s.peerCerts = append(s.peerCerts, tc.ConnectionState().PeerCertificates...)
}

func (s *fakeServer) record(line string) {
	s.mu.Lock()
	s.lines = append(s.lines, line)
	s.mu.Unlock()
}

func splitAddr(v string) (addr, params string) {
	if i := strings.Index(v, ">"); i >= 0 {
		return v[:i+1], strings.TrimSpace(v[i+1:])
	}
	return v, ""
}

// readData reads a dot-terminated body and removes dot-stuffing.
func readData(r *bufio.Reader) ([]byte, error) {
	var out bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" {
			return out.Bytes(), nil
		}
		out.WriteString(strings.TrimPrefix(line, "."))
	}
}

// auth handles AUTH PLAIN / LOGIN; false means close the connection.
func (s *fakeServer) auth(conn net.Conn, r *bufio.Reader, line string, reply func(string)) bool {
	readLine := func() (string, bool) {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", false
		}
		l = strings.TrimRight(l, "\r\n")
		s.record(l)
		return l, true
	}
	decode := func(v string) (string, bool) {
		b, err := base64.StdEncoding.DecodeString(v)
		return string(b), err == nil
	}
	fields := strings.Fields(line)
	mech := strings.ToUpper(fields[1])
	if !strings.Contains(" "+s.opts.AuthMechs+" ", " "+mech+" ") {
		reply("504 5.5.4 mechanism not supported")
		return true
	}
	var user, pass string
	switch mech {
	case "PLAIN":
		var resp string
		if len(fields) > 2 {
			resp = fields[2]
		} else {
			reply("334 ")
			var ok bool
			if resp, ok = readLine(); !ok {
				return false
			}
		}
		dec, ok := decode(resp)
		parts := strings.Split(dec, "\x00")
		if !ok || len(parts) != 3 {
			reply("501 5.5.2 bad PLAIN response")
			return true
		}
		user, pass = parts[1], parts[2]
	case "LOGIN":
		var u string
		if len(fields) > 2 {
			u = fields[2]
		} else {
			reply("334 VXNlcm5hbWU6")
			var ok bool
			if u, ok = readLine(); !ok {
				return false
			}
		}
		reply("334 UGFzc3dvcmQ6")
		p, ok := readLine()
		if !ok {
			return false
		}
		user, _ = decode(u)
		pass, _ = decode(p)
	}
	if user == s.opts.User && pass == s.opts.Pass {
		reply("235 2.7.0 Authentication successful")
	} else {
		reply("535 5.7.8 Authentication credentials invalid")
	}
	return true
}

// snapshot accessors

func (s *fakeServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *fakeServer) rawBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.raw.Bytes()...)
}

func (s *fakeServer) ehloNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ehlo...)
}

type received struct {
	MailFrom  string
	Params    string
	Rcpts     []string
	Data      []byte
	Delivered bool
}

func (s *fakeServer) received() received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return received{s.mailFrom, s.mailParams, append([]string(nil), s.rcpts...), append([]byte(nil), s.data...), s.delivered}
}

func (s *fakeServer) clientCerts() []*x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*x509.Certificate(nil), s.peerCerts...)
}

func (s *fakeServer) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connCount
}

// sawAny reports whether any command line starts with one of the prefixes (case-insensitive).
func (s *fakeServer) sawAny(prefixes ...string) bool {
	for _, l := range s.commands() {
		u := strings.ToUpper(l)
		for _, p := range prefixes {
			if strings.HasPrefix(u, p) {
				return true
			}
		}
	}
	return false
}

// leaked reports whether the credentials reached the server in any form:
// plain or base64 (as PLAIN blob or LOGIN steps), in a parsed command line
// or in the raw socket bytes, or whether the client even started AUTH.
func (s *fakeServer) leaked(user, pass string) bool {
	if s.sawAny("AUTH") {
		return true
	}
	enc := base64.StdEncoding.EncodeToString
	needles := []string{pass, enc([]byte(pass)), enc([]byte(user)), enc([]byte("\x00" + user + "\x00" + pass))}
	raw := s.rawBytes()
	for _, n := range needles {
		if bytes.Contains(raw, []byte(n)) {
			return true
		}
		for _, l := range s.commands() {
			if strings.Contains(l, n) {
				return true
			}
		}
	}
	return false
}
