package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// envRef matches ${NAME} only; a bare $NAME is deliberately left alone.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

var yamlLine = regexp.MustCompile(`^line (\d+): (.*)$`)

// Load reads, expands, strictly decodes, defaults and validates a config file.
// Validation problems are returned as *ValidationError.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded, err := expandEnv(raw)
	if err != nil {
		return nil, err
	}

	cfg, err := decodeStrict(expanded)
	if err != nil {
		return nil, err
	}
	if err := cfg.applyDefaults(); err != nil {
		return nil, &ValidationError{Errors: []string{"server.hostname: cannot determine system hostname: " + err.Error()}}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// expandEnv replaces ${NAME} inside YAML scalar values (not keys). Working on
// the parsed tree keeps secrets containing YAML metacharacters from breaking
// the document. Unset variables are reported by name, never by value.
func expandEnv(raw []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind == 0 {
		return raw, nil
	}

	var errs []string
	walk(&doc, "", func(n *yaml.Node, path string, key bool) {
		if key || n.Tag != "!!str" || !strings.Contains(n.Value, "${") {
			return
		}
		n.Value = envRef.ReplaceAllStringFunc(n.Value, func(ref string) string {
			name := envRef.FindStringSubmatch(ref)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: environment variable %s is not set", path, name))
			}
			return v
		})
		// Let a plain "${PORT}" expanding to 587 (or "true") decode into int/bool fields.
		if n.Style == 0 && isIntOrBool(n.Value) {
			n.Tag = ""
		}
	})
	if len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("re-encode config: %w", err)
	}
	return out, nil
}

func isIntOrBool(s string) bool {
	if s == "true" || s == "false" {
		return true
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

func decodeStrict(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(cfg)
	if err == nil || errors.Is(err, io.EOF) {
		return cfg, nil
	}

	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var doc yaml.Node
	_ = yaml.Unmarshal(data, &doc)
	lines := map[int]string{}
	walk(&doc, "", func(n *yaml.Node, path string, _ bool) { lines[n.Line] = path })

	ve := &ValidationError{}
	for _, msg := range te.Errors {
		ve.Errors = append(ve.Errors, describeTypeError(msg, lines))
	}
	return nil, ve
}

// describeTypeError turns "line 7: field foo not found in type config.X" into
// "server.foo: unknown key".
func describeTypeError(msg string, lines map[int]string) string {
	m := yamlLine.FindStringSubmatch(msg)
	if m == nil {
		return msg
	}
	line, _ := strconv.Atoi(m[1])
	rest := m[2]
	if strings.HasPrefix(rest, "field ") && strings.Contains(rest, " not found in type ") {
		rest = "unknown key"
	}
	if p := lines[line]; p != "" {
		return p + ": " + rest
	}
	return fmt.Sprintf("line %d: %s", line, rest)
}

func walk(n *yaml.Node, path string, fn func(n *yaml.Node, path string, key bool)) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walk(c, path, fn)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			p := k.Value
			if path != "" {
				p = path + "." + k.Value
			}
			fn(k, p, true)
			walk(v, p, fn)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			walk(c, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case yaml.ScalarNode:
		fn(n, path, false)
	}
}
