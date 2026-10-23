package server

import (
	"crypto/tls"
	"fmt"
)

// tlsConfigFor builds the server TLS configuration for a profile name
// (spec 6.5). The cipher list only affects TLS 1.2 and older; TLS 1.3 suites
// are fixed by Go.
func tlsConfigFor(profile string, cert tls.Certificate) (*tls.Config, error) {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	switch profile {
	case "", "default":
	case "modern":
		cfg.MinVersion = tls.VersionTLS13
	case "intermediate":
		cfg.MinVersion = tls.VersionTLS12
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	case "legacy":
		cfg.MinVersion = tls.VersionTLS10
		for _, s := range tls.CipherSuites() {
			cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
		}
		for _, s := range tls.InsecureCipherSuites() {
			cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
		}
	default:
		return nil, fmt.Errorf("unknown tls profile %q", profile)
	}
	return cfg, nil
}
