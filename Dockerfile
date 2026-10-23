# syntax=docker/dockerfile:1

# GO_VERSION must be at least the `go` directive in go.mod.
ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.24

# ---- build ----
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
      -o /out/smtp-relay ./cmd/smtp-relay

# ---- runtime ----
FROM alpine:${ALPINE_VERSION}

# ca-certificates: verify upstream TLS certificates. tzdata: correct log timestamps if TZ is set.
# The state directory is created and chowned BEFORE the VOLUME instruction: a new named
# volume copies its ownership (UID 10001) from this directory on first mount.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 smtp-relay \
 && adduser -S -u 10001 -G smtp-relay -H -s /sbin/nologin smtp-relay \
 && mkdir -p /etc/smtp-relay /var/lib/smtp-relay /var/log/smtp-relay \
 && chown smtp-relay:smtp-relay /var/lib/smtp-relay /var/log/smtp-relay

COPY --from=build /out/smtp-relay /usr/local/bin/smtp-relay

USER smtp-relay:smtp-relay

# Unprivileged ports: the container runs as a non-root user, so it cannot bind port 25.
# Publish it from the host instead (see docker-compose.yaml: "25:2525").
# 9090 is the metrics port; it only answers when metrics.enabled is true.
EXPOSE 2525 9090

VOLUME ["/var/lib/smtp-relay"]

# No HEALTHCHECK here on purpose: /healthz exists only when metrics are enabled, so the
# check lives in docker-compose.yaml. Keep logging.output: stdout; under the compose
# file's read_only root filesystem /var/log/smtp-relay is not writable.
ENTRYPOINT ["/usr/local/bin/smtp-relay"]
CMD ["-config", "/etc/smtp-relay/config.yaml"]
