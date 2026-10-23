package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultPath = "/metrics"
	healthPath  = "/healthz"
	readyPath   = "/readyz"
)

// Server serves the metrics endpoint plus /healthz and /readyz.
type Server struct {
	addr  string
	path  string
	m     *Metrics
	ready func() bool

	mu  sync.Mutex
	srv *http.Server
	ln  net.Listener
}

// NewServer prepares a server; nothing is bound until Start. A nil ready
// function means always ready.
func NewServer(addr, path string, m *Metrics, ready func() bool) *Server {
	if path == "" {
		path = defaultPath
	}
	return &Server{addr: addr, path: path, m: m, ready: ready}
}

// Start binds the listener synchronously and serves in the background.
func (s *Server) Start() error {
	if s.path[0] != '/' || s.path == healthPath || s.path == readyPath {
		return fmt.Errorf("metrics path %q is invalid: must start with / and not be %s or %s", s.path, healthPath, readyPath)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return errors.New("metrics server already started")
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("metrics listen %s: %w", s.addr, err)
	}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.srv, s.ln = srv, ln
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// Addr returns the bound address, or nil before Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown stops serving, waiting for in-flight requests until ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

func (s *Server) handler() http.Handler {
	metricsHandler := promhttp.HandlerFor(s.m.Registry(), promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case s.path:
			metricsHandler.ServeHTTP(w, r)
		case healthPath:
			writeText(w, http.StatusOK, "ok\n")
		case readyPath:
			if s.ready == nil || s.ready() {
				writeText(w, http.StatusOK, "ok\n")
			} else {
				writeText(w, http.StatusServiceUnavailable, "not ready\n")
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func writeText(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}
