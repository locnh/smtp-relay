// Package server implements the SMTP listening side of the relay.
package server

import (
	"net"
	"strings"

	"github.com/locnh/smtp-relay/internal/config"
)

// Policy decides which client networks and envelope senders may use the relay.
// It is immutable after NewPolicy and safe for concurrent use.
type Policy struct {
	networks      []*net.IPNet
	senders       map[string]struct{}
	senderDomains map[string]struct{}
	// restricted is decided from the raw config, so a list holding only blank
	// entries still restricts senders instead of opening the relay.
	restricted bool
}

// NewPolicy copies and normalises the access configuration.
func NewPolicy(a config.AccessConfig) *Policy {
	return &Policy{
		networks:      append([]*net.IPNet(nil), a.Networks...),
		senders:       toSet(a.AllowedSenders),
		senderDomains: toSet(a.AllowedSenderDomains),
		restricted:    len(a.AllowedSenders) > 0 || len(a.AllowedSenderDomains) > 0,
	}
}

// NetworkAllowed reports whether ip may connect. An empty network list allows
// every address (open relay); the caller is expected to warn about this at startup.
func (p *Policy) NetworkAllowed(ip net.IP) bool {
	if len(p.networks) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range p.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SenderAllowed reports whether addr, a bare envelope address without angle
// brackets, may send through the relay. The null sender is always rejected.
func (p *Policy) SenderAllowed(addr string) bool {
	addr = normalise(addr)
	if addr == "" || addr == "<>" {
		return false
	}
	if !p.restricted {
		return true
	}
	if _, ok := p.senders[addr]; ok {
		return true
	}
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	_, ok := p.senderDomains[addr[at+1:]]
	return ok
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v = normalise(v); v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}

func normalise(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
