package config

import "encoding/json"

// Secret is a string that never prints itself. Use Reveal to get the value.
// It guards against accidental leaks through fmt, JSON, YAML and loggers.
type Secret string

const redacted = "***"

// Reveal returns the real value.
func (s Secret) Reveal() string { return string(s) }

// String implements fmt.Stringer.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (s Secret) GoString() string { return `config.Secret("` + redacted + `")` }

// MarshalText implements encoding.TextMarshaler.
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON implements json.Marshaler.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// MarshalYAML implements yaml.Marshaler.
func (s Secret) MarshalYAML() (any, error) { return redacted, nil }
