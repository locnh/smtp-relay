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

// Load reads, expands, strictly decodes, defaults and validates a config file.
// Validation problems are returned as *ValidationError; I/O and YAML syntax
// problems are plain errors.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	data, doc, err := expandEnv(raw)
	if err != nil {
		return nil, err
	}

	cfg, err := decodeStrict(data)
	if err != nil {
		return nil, err
	}

	present := map[string]bool{}
	walk(doc, "", func(_ *yaml.Node, path string, key bool) {
		if key {
			present[path] = true
		}
	})
	if err := cfg.applyDefaults(present); err != nil {
		return nil, &ValidationError{Errors: []string{"server.hostname: cannot determine system hostname: " + err.Error()}}
	}
	if err := cfg.validate(present); err != nil {
		return nil, err
	}
	return cfg, nil
}

// expandEnv replaces ${NAME} inside YAML scalar values (not keys, not
// comments). Each reference is first swapped for a plain-scalar-safe sentinel
// so the document parses even when "${...}" sits in flow style (the "}" would
// otherwise end the mapping). Real values are then written into the parsed
// tree, so a secret containing YAML metacharacters can never alter the
// document structure, and expanded values are never expanded again. Unset
// variables are reported by name, never by value.
func expandEnv(raw []byte) ([]byte, *yaml.Node, error) {
	prefix := "__SMTPRELAY_ENV"
	for bytes.Contains(raw, []byte(prefix)) {
		prefix += "X"
	}
	var names []string
	masked := envRef.ReplaceAllFunc(raw, func(ref []byte) []byte {
		names = append(names, string(envRef.FindSubmatch(ref)[1]))
		return []byte(fmt.Sprintf("%s_%d__", prefix, len(names)-1))
	})
	sentinel := regexp.MustCompile(regexp.QuoteMeta(prefix) + `_(\d+)__`)

	var doc yaml.Node
	if err := yaml.Unmarshal(masked, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind == 0 {
		return raw, &doc, nil
	}

	var errs []string
	walk(&doc, "", func(n *yaml.Node, path string, key bool) {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" || !sentinel.MatchString(n.Value) {
			return
		}
		if key {
			n.Value = sentinel.ReplaceAllStringFunc(n.Value, func(s string) string {
				return "${" + names[sentinelIndex(sentinel, s)] + "}"
			})
			return
		}
		whole := sentinel.FindString(n.Value) == n.Value
		n.Value = sentinel.ReplaceAllStringFunc(n.Value, func(s string) string {
			name := names[sentinelIndex(sentinel, s)]
			v, ok := os.LookupEnv(name)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: environment variable %s is not set", path, name))
			}
			return v
		})
		switch {
		case whole && n.Style == 0 && isIntOrBool(n.Value):
			// "port: ${PORT}" must still decode into an int field.
			n.Tag = ""
		case n.Style == 0:
			n.Style = yaml.DoubleQuotedStyle
		}
	})
	if len(errs) > 0 {
		return nil, nil, &ValidationError{Errors: errs}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, nil, fmt.Errorf("re-encode config: %w", err)
	}
	return out, &doc, nil
}

func sentinelIndex(re *regexp.Regexp, s string) int {
	i, _ := strconv.Atoi(re.FindStringSubmatch(s)[1])
	return i
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
	byLine := map[int][]located{}
	walk(&doc, "", func(n *yaml.Node, path string, key bool) {
		byLine[n.Line] = append(byLine[n.Line], located{n, path, key})
	})

	ve := &ValidationError{}
	for _, msg := range te.Errors {
		ve.Errors = append(ve.Errors, describeTypeError(msg, byLine))
	}
	return nil, ve
}

type located struct {
	node *yaml.Node
	path string
	key  bool
}

var (
	yamlLine     = regexp.MustCompile(`^line (\d+): (.*)$`)
	unknownField = regexp.MustCompile(`^field (\S+) not found in type `)
	duplicateKey = regexp.MustCompile(`^mapping key "(.*)" already defined at line `)
	cannotDecode = regexp.MustCompile("^cannot unmarshal (\\S+)(?: `(.*)`)? into (.+)$")
)

// describeTypeError rewrites a go-yaml message into "<key path>: <problem>".
// The decoder echoes the offending value in its messages, which may be an
// expanded secret, so the output is built only from the path, the expected
// type and the kind of value found, never from the value itself.
func describeTypeError(msg string, byLine map[int][]located) string {
	m := yamlLine.FindStringSubmatch(msg)
	if m == nil {
		return "invalid configuration value"
	}
	line, _ := strconv.Atoi(m[1])
	rest := m[2]
	cands := byLine[line]

	// Several nodes can match on one line; the last one in document order is
	// the most deeply nested, which is the one that failed to decode (a parent
	// that failed would not have had its children decoded at all).
	find := func(match func(l located) bool) (string, bool) {
		for i := len(cands) - 1; i >= 0; i-- {
			if match(cands[i]) {
				return cands[i].path, true
			}
		}
		return "", false
	}
	at := func(path string, ok bool, problem string) string {
		if !ok {
			return fmt.Sprintf("line %d: %s", line, problem)
		}
		return path + ": " + problem
	}

	if f := unknownField.FindStringSubmatch(rest); f != nil {
		p, ok := find(func(l located) bool { return l.key && l.node.Value == f[1] })
		return at(p, ok, "unknown key")
	}
	if d := duplicateKey.FindStringSubmatch(rest); d != nil {
		p, ok := find(func(l located) bool { return l.key && l.node.Value == d[1] })
		return at(p, ok, "duplicate key")
	}
	if c := cannotDecode.FindStringSubmatch(rest); c != nil {
		tag, shown, goType := c[1], c[2], c[3]
		wantPrefix := strings.TrimSuffix(shown, "...")
		p, ok := find(func(l located) bool {
			return !l.key && l.node.ShortTag() == tag && strings.HasPrefix(l.node.Value, wantPrefix)
		})
		return at(p, ok, fmt.Sprintf("expected %s, got %s", expectedKind(goType), foundKind(tag)))
	}
	return at("", false, "invalid configuration value")
}

func foundKind(tag string) string {
	switch tag {
	case "!!str":
		return "string"
	case "!!int":
		return "integer"
	case "!!float":
		return "float"
	case "!!bool":
		return "boolean"
	case "!!seq":
		return "list"
	case "!!map":
		return "mapping"
	case "!!null":
		return "null"
	}
	return "other value"
}

func expectedKind(goType string) string {
	switch {
	case goType == "time.Duration":
		return "duration such as 30s"
	case goType == "string" || goType == "config.Secret":
		return "string"
	case goType == "bool" || goType == "*bool":
		return "boolean"
	case strings.HasPrefix(goType, "int") || strings.HasPrefix(goType, "uint"):
		return "integer"
	case strings.HasPrefix(goType, "[]"):
		return "list"
	}
	return "mapping"
}

// walk calls fn for every node: mapping keys (key=true), scalar values and
// collections, each with its YAML key path such as "upstreams[1].auth.password".
func walk(n *yaml.Node, path string, fn func(n *yaml.Node, path string, key bool)) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walk(c, path, fn)
		}
	case yaml.MappingNode:
		fn(n, path, false)
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
		fn(n, path, false)
		for i, c := range n.Content {
			walk(c, fmt.Sprintf("%s[%d]", path, i), fn)
		}
	case yaml.ScalarNode:
		fn(n, path, false)
	}
}
