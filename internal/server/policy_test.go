package server

import (
	"net"
	"testing"

	"github.com/locnh/smtp-relay/internal/config"
	"github.com/stretchr/testify/assert"
)

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %s: %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

func TestPolicyNetworkAllowed(t *testing.T) {
	tests := []struct {
		name     string
		networks []string
		ip       net.IP
		want     bool
	}{
		{"ipv4 inside", []string{"192.168.1.0/24"}, net.ParseIP("192.168.1.5"), true},
		{"ipv4 outside", []string{"192.168.1.0/24"}, net.ParseIP("192.168.2.5"), false},
		{"ipv6 inside", []string{"2001:db8::/32"}, net.ParseIP("2001:db8::1"), true},
		{"ipv6 outside", []string{"2001:db8::/32"}, net.ParseIP("2001:db9::1"), false},
		{"ipv6 client not in ipv4 cidr", []string{"192.168.1.0/24"}, net.ParseIP("2001:db8::1"), false},
		{"ipv4-mapped ipv6 matches ipv4 cidr", []string{"192.168.1.0/24"}, net.ParseIP("::ffff:192.168.1.5"), true},
		{"ipv4-mapped ipv6 outside ipv4 cidr", []string{"192.168.1.0/24"}, net.ParseIP("::ffff:10.0.0.1"), false},
		{"any of several cidrs", []string{"10.0.0.0/8", "192.168.1.0/24"}, net.ParseIP("192.168.1.9"), true},
		{"empty list allows all", nil, net.ParseIP("203.0.113.7"), true},
		{"empty list allows nil ip", nil, nil, true},
		{"nil ip rejected when restricted", []string{"192.168.1.0/24"}, nil, false},
		{"invalid ip rejected when restricted", []string{"192.168.1.0/24"}, net.IP{1, 2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPolicy(config.AccessConfig{Networks: mustCIDRs(t, tt.networks...)})
			assert.Equal(t, tt.want, p.NetworkAllowed(tt.ip))
		})
	}
}

func TestPolicySenderAllowed(t *testing.T) {
	tests := []struct {
		name    string
		senders []string
		domains []string
		addr    string
		want    bool
	}{
		{"null sender, empty lists", nil, nil, "", false},
		{"null sender literal, empty lists", nil, nil, "<>", false},
		{"null sender, with senders", []string{"a@example.com"}, nil, "", false},
		{"null sender, with domains", nil, []string{"example.com"}, "<>", false},
		{"both lists empty allows any", nil, nil, "anyone@anywhere.org", true},
		{"exact address", []string{"alerts@example.com"}, nil, "alerts@example.com", true},
		{"other address in same domain not in senders", []string{"alerts@example.com"}, nil, "bob@example.com", false},
		{"domain entry matches", nil, []string{"example.com"}, "bob@example.com", true},
		{"address case differs from entry", []string{"Alerts@Example.com"}, nil, "alerts@example.COM", true},
		{"domain case differs from entry", nil, []string{"EXAMPLE.com"}, "bob@Example.Com", true},
		{"subdomain does not match domain entry", nil, []string{"example.com"}, "bob@mail.example.com", false},
		{"parent of domain entry does not match", nil, []string{"mail.example.com"}, "bob@example.com", false},
		{"no-@ address matches senders exactly", []string{"postmaster"}, nil, "postmaster", true},
		{"no-@ address never matches domain entry", nil, []string{"localhost"}, "localhost", false},
		{"multiple @ uses last part as domain", nil, []string{"example.com"}, "a@b@example.com", true},
		{"multiple @ does not use first part", nil, []string{"b"}, "a@b@example.com", false},
		{"surrounding whitespace trimmed in address", []string{"alerts@example.com"}, nil, "  alerts@example.com \t", true},
		{"surrounding whitespace trimmed in entry", []string{"  alerts@example.com "}, nil, "alerts@example.com", true},
		{"senders only, address matches domain", []string{"alerts@example.com"}, nil, "bob@other.org", false},
		{"domains only, address matches sender", nil, []string{"example.com"}, "alerts@other.org", false},
		{"entry in senders with empty domain list", []string{"alerts@example.com"}, []string{}, "alerts@example.com", true},
		{"entry in domains with empty sender list", []string{}, []string{"example.com"}, "x@example.com", true},
		{"blank entries only still restrict", []string{"  "}, nil, "bob@example.com", false},
		{"matches neither list", []string{"alerts@example.com"}, []string{"example.org"}, "bob@example.net", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPolicy(config.AccessConfig{
				AllowedSenders:       tt.senders,
				AllowedSenderDomains: tt.domains,
			})
			assert.Equal(t, tt.want, p.SenderAllowed(tt.addr))
		})
	}
}
