package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

const rejectWriteTimeout = time.Second

// gate admits or rejects raw TCP connections before the SMTP (or TLS) layer
// sees them. One gate is shared by all listeners so max_connections is global.
type gate struct {
	policy *Policy
	max    int // < 0 means unlimited
	events Events
	log    zerolog.Logger

	active atomic.Int64
	mu     sync.Mutex
	open   map[*gatedConn]struct{}
}

func newGate(p *Policy, max int, ev Events, log zerolog.Logger) *gate {
	return &gate{policy: p, max: max, events: ev, log: log, open: make(map[*gatedConn]struct{})}
}

func (g *gate) wrap(name string, l net.Listener) net.Listener {
	return &gatedListener{Listener: l, g: g, name: name}
}

// closeIdle closes admitted connections that are not inside a mail transaction.
func (g *gate) closeIdle() {
	g.mu.Lock()
	var idle []*gatedConn
	for c := range g.open {
		if !c.busy.Load() {
			idle = append(idle, c)
		}
	}
	g.mu.Unlock()
	for _, c := range idle {
		c.Close()
	}
}

// closeAll force-closes every admitted connection that is still open.
func (g *gate) closeAll() {
	g.mu.Lock()
	conns := make([]*gatedConn, 0, len(g.open))
	for c := range g.open {
		conns = append(conns, c)
	}
	g.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func (g *gate) acquire() bool {
	if g.max < 0 {
		g.active.Add(1)
		return true
	}
	for {
		cur := g.active.Load()
		if cur >= int64(g.max) {
			return false
		}
		if g.active.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// admit returns the wrapped connection, or nil after rejecting c.
func (g *gate) admit(name string, c net.Conn) net.Conn {
	peer := peerIP(c.RemoteAddr())
	if !g.policy.NetworkAllowed(net.ParseIP(peer)) {
		g.reject(c, name, "denied_network", "554 5.7.1 Access denied")
		g.log.Warn().Str("peer", peer).Str("listener", name).Msg("connection denied: network not allowed")
		return nil
	}
	if !g.acquire() {
		g.reject(c, name, "rejected_limit", "421 4.7.0 Too many connections")
		g.log.Warn().Str("peer", peer).Str("listener", name).Msg("connection rejected: max_connections reached")
		return nil
	}
	gc := &gatedConn{Conn: c, g: g, name: name}
	g.mu.Lock()
	g.open[gc] = struct{}{}
	g.mu.Unlock()
	g.events.ConnAccepted(name)
	return gc
}

// reject writes a one-line reply on a fresh socket (cannot block for long
// thanks to the deadline) and closes it, so the accept loop is never held up.
func (g *gate) reject(c net.Conn, name, result, reply string) {
	g.events.ConnRejected(name, result)
	_ = c.SetWriteDeadline(time.Now().Add(rejectWriteTimeout))
	_, _ = c.Write([]byte(reply + "\r\n"))
	_ = c.Close()
}

type gatedListener struct {
	net.Listener
	g    *gate
	name string
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if gc := l.g.admit(l.name, c); gc != nil {
			return gc, nil
		}
	}
}

// gatedConn releases its connection slot and reports ConnClosed exactly once.
type gatedConn struct {
	net.Conn
	g    *gate
	name string

	// busy is true between an accepted MAIL FROM and the end of the transaction.
	busy atomic.Bool
	once sync.Once
	err  error
}

func (c *gatedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.g.mu.Lock()
		delete(c.g.open, c)
		c.g.mu.Unlock()
		c.g.active.Add(-1)
		c.g.events.ConnClosed(c.name)
	})
	return c.err
}

func peerIP(a net.Addr) string {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
