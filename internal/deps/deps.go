// Package deps keeps module requirements pinned while packages are still being
// written in parallel. Remove this package once every dependency is imported by
// real code (task 12), then run `go mod tidy`.
package deps

import (
	_ "github.com/DeRuina/timberjack"
	_ "github.com/emersion/go-smtp"
	_ "github.com/google/uuid"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/prometheus/client_golang/prometheus/testutil"
	_ "github.com/rs/zerolog"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/require"
	_ "go.yaml.in/yaml/v3"
)
