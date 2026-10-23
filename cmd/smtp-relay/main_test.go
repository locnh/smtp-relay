package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealMain(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(good, []byte("upstreams: [{name: a, host: h}]\n"), 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("upstreams: [{name: A, host: h}]\n"), 0o600))

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = busy.Close() })
	inUse := filepath.Join(dir, "inuse.yaml")
	require.NoError(t, os.WriteFile(inUse, []byte("server: {listen: [{address: \""+busy.Addr().String()+"\"}]}\nupstreams: [{name: a, host: h}]\n"), 0o600))

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"-version"}, 0, "smtp-relay/dev (unknown)\n", ""},
		{"missing config", nil, 2, "", "-config is required"},
		{"unknown flag", []string{"-nope"}, 2, "", "flag provided but not defined"},
		{"check ok", []string{"-config", good, "-check-config"}, 0, "config OK\n", ""},
		{"check invalid", []string{"-config", bad, "-check-config"}, 1, "", "upstreams[0].name: must match"},
		{"missing file", []string{"-config", filepath.Join(dir, "none.yaml"), "-check-config"}, 1, "", "smtp-relay: read config"},
		{"extra positional arg", []string{"-config", good, "extra"}, 2, "", `unexpected argument "extra"`},
		{"run invalid config", []string{"-config", bad}, 1, "", "invalid configuration"},
		{"run listen address in use", []string{"-config", inUse}, 1, "", "smtp-relay: server: listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := realMain(tt.args, &out, &errOut)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantStdout, out.String())
			assert.Contains(t, errOut.String(), tt.wantStderr)
			if tt.name == "missing file" {
				assert.NotContains(t, errOut.String(), "invalid configuration")
			}
		})
	}
}
