# smtp-relay

A small SMTP relay for your local network.

Point your services at `smtp-relay` and forget about SMTP credentials. The relay
holds the credentials and handles **TLS and authentication** towards a real SMTP
server (Gmail / Google Workspace, Amazon SES, SMTP2GO, Mailgun, ...). Your cron
jobs, printers, scripts and apps only need the relay's `host:port`: no username,
no password, no TLS settings.

> **Status:** under development. This README describes the target behaviour
> defined in [`spec.md`](spec.md); the implementation plan is in
> [`tasks/`](tasks/). Sections marked *(planned)* are not built yet.

```
 cron / printer / app          smtp-relay                      real SMTP server
 ┌──────────────────┐   plain  ┌───────────────┐   TLS + auth  ┌─────────────────┐
 │  no credentials  │ ───────▶ │  access check │ ────────────▶ │ Gmail / SES /   │
 │  no TLS needed   │  :25     │  failover     │               │ SMTP2GO / ...   │
 └──────────────────┘          │  log + metrics│  on failure   └─────────────────┘
                               └──────┬────────┘ ──▶ next upstream
                                      │
                                      └─ /metrics (Prometheus)
```

## Why

- Credentials live in **one place** instead of every device and script.
- No Postfix/Exim to install, tune and patch.
- Many embedded devices only speak plain SMTP, or have outdated TLS. The relay
  accepts them and talks modern TLS upstream.
- Several upstreams in priority order, so one provider outage does not lose mail.
- One log line per mail, plus metrics, so you can see whether mail is getting out.

## Features

- Accepts SMTP on any number of listeners: plain, STARTTLS, or implicit TLS; IPv4 and IPv6.
- Forwards to real SMTP servers over TLS with `PLAIN` / `LOGIN` authentication.
- **Failover** across upstreams, in the order you list them.
- **Access control** by source network, and by sender address or domain.
- **Messages are forwarded unchanged**: envelope, headers and body are not modified.
- One **summary log line per mail** (`from`, `to`, `subj`, `status`), text or JSON.
- **Prometheus metrics** and health endpoints, including soft quota usage per upstream.
- YAML configuration with strict validation and `-check-config`.
- Secrets from environment variables or files; never logged.
- Single static binary, or a small Docker image running as non-root.

## What it does not do

Knowing the limits helps you decide whether this fits.

- **No queue and no retries.** If every upstream fails, the sender gets an error and
  must retry on its own (cron, msmtp, most apps do). Nothing is stored on disk.
- **No client authentication.** Anyone who can reach the port from an allowed network
  can send mail. See [Security](#security).
- **No message rewriting**: no `Received` header, no `From` change, no DKIM signing.
- No recipient filtering, no aliases, no local delivery. It is not an MTA.
- Not a bulk-mail or newsletter engine.

## Install

### Binary

Requires Go 1.27 or newer.

```sh
go install github.com/locnh/smtp-relay/cmd/smtp-relay@latest
# or from a checkout:
go build -o smtp-relay ./cmd/smtp-relay
```

### Docker

```sh
docker build -t smtp-relay .
```

## Quick start

### Binary

1. Copy the example config and edit it:

   ```sh
   cp config.example.yaml config.yaml
   ```

2. Export the credentials the config refers to (`${SES_SMTP_USER}` etc.):

   ```sh
   export SES_SMTP_USER=...
   export SES_SMTP_PASS=...
   ```

3. Check it, then run:

   ```sh
   ./smtp-relay -config config.yaml -check-config
   ./smtp-relay -config config.yaml
   ```

### Docker Compose

```sh
cp config.docker.example.yaml config.yaml    # edit upstreams, allowed_networks, hostname
cat > .env <<'EOF'
UPSTREAM1_USER=your-smtp-username
UPSTREAM1_PASS=your-smtp-password
EOF

docker compose run --rm smtp-relay -config /etc/smtp-relay/config.yaml -check-config
docker compose up -d
docker compose logs -f
```

The container listens on port **2525** (a non-root process cannot bind port 25) and
Compose publishes it as host port **25**. Edit the `ports:` entry to change that, or
to bind a single LAN address, for example `"192.168.1.10:25:2525"`.

Keep `.env` and `config.yaml` out of version control (both are in `.gitignore`).

### Send a test mail

```sh
# swaks (https://www.jetmore.org/john/code/swaks/)
swaks --server 127.0.0.1:25 --from noreply@example.com --to you@example.org \
      --header "Subject: relay test" --body "hello"

# or with curl
printf 'From: noreply@example.com\r\nTo: you@example.org\r\nSubject: relay test\r\n\r\nhello\r\n' |
  curl --url smtp://127.0.0.1:25 --mail-from noreply@example.com \
       --mail-rcpt you@example.org --upload-file -
```

You should see one summary line in the relay's log:

```
2026-10-22T10:15:03Z INF mail from=noreply@example.com to=[you@example.org] subj="relay test" status=delivered upstream=ses-eu attempts=1 size=187 duration_ms=420 peer=192.168.1.20 uuid=3f1c...
```

## Configuring your services

Point them at the relay with **no authentication and no encryption**:

| Setting | Value |
|---|---|
| SMTP server / host | the relay's IP or name |
| Port | `25` (or whatever you published) |
| Encryption / TLS | none |
| Username / password | none |
| From address | one allowed by `access.allowed_senders` / `allowed_sender_domains` |

Examples:

```ini
# msmtp (~/.msmtprc)
account default
host relay.home.lan
port 25
from alerts@example.com
auth off
tls off
```

```sh
# cron
MAILTO=ops@example.com
# set the sender through your MTA/msmtp configuration
```

> The From address must be accepted by your **upstream provider** too, because the
> relay does not change it. See [Provider notes](#provider-notes).

## Configuration

Everything is in one YAML file, passed with `-config`. See
[`config.example.yaml`](config.example.yaml) (binary) and
[`config.docker.example.yaml`](config.docker.example.yaml) (Docker) for complete,
commented examples.

```sh
smtp-relay -config config.yaml -check-config   # validate and exit (0 = ok, 1 = errors)
smtp-relay -config config.yaml                 # run
smtp-relay -version
```

Rules:

- **Strict:** an unknown key is an error, so typos do not pass silently.
- **`${NAME}`** is replaced by the environment variable `NAME`. A bare `$NAME` is left
  alone. An unset variable is an error.
- Every secret has a `*_file` form (for example `password_file`) for Docker/Kubernetes
  secrets. Set one or the other, not both.
- Durations use Go syntax: `30s`, `5m`, `24h`.
- All errors are reported together, with the path of the offending key, for example
  `upstreams[1].auth.password`. Secret values are never printed.
- Configuration changes need a restart.

### Sections

| Section | Purpose |
|---|---|
| `server` | Hostname, listeners (`none` / `starttls` / `tls`), TLS certificate and profile, timeouts, limits |
| `access` | `allowed_networks`, `allowed_senders`, `allowed_sender_domains` |
| `upstreams` | Real SMTP servers in priority order: host, port, `tls`, `auth`, `tls_options`, `timeouts`, `quota` |
| `state` | File holding quota counters (required if any upstream has a `quota`) |
| `logging` | `level`, `format` (`text` / `json`), `output` (`stdout` / `stderr` / `file`) |
| `metrics` | Enable, listen address, path |

### Upstream TLS modes

| `tls` | Behaviour |
|---|---|
| `starttls` | Connect, then **require** STARTTLS. If the server does not offer it, the attempt fails and nothing is sent (credentials included). Usually port 587. |
| `tls` | TLS from the first byte (implicit TLS). Usually port 465. |
| `none` | No encryption. Development or a trusted internal hop only. |

- Certificates are verified by default. `insecure_skip_verify: true` turns that off
  and logs a warning at startup.
- Credentials are **never sent over an unencrypted connection**, for `PLAIN` and
  `LOGIN` alike, unless you set `allow_insecure_auth: true`.
- `mechanism: auto` uses `PLAIN` when the server offers it and `LOGIN` otherwise.
- Mutual TLS: set both `client_cert_file` and `client_key_file` on the upstream.
- The relay introduces itself to upstreams with `server.hostname` in `EHLO`. Use a
  real FQDN; some providers check it.

### Access control

```yaml
access:
  allowed_networks: [192.168.0.0/16, 10.0.0.0/8]
  allowed_senders: [noreply@example.com]
  allowed_sender_domains: [example.com]
```

- A connection from outside `allowed_networks` is refused. The default is loopback only.
- A `MAIL FROM` must match `allowed_senders` (exact address) **or**
  `allowed_sender_domains` (exact domain, subdomains do not match). If both lists
  are empty, any sender is accepted.
- Matching is case-insensitive. The null sender `<>` is always rejected.

## Failover

Upstreams are tried **in the order listed**. The first success ends the attempt, so a
mail is delivered once. On any failure (connection, TLS, authentication, timeout, 4xx
or 5xx) the relay logs a warning and moves to the next one. If all fail, the client
gets the error from the last upstream: SMTP errors keep their code and message, other
failures become `421 4.4.0 Forwarding failed`. Details such as upstream host names
only go to the log.

The order is fixed; quota, latency or past failures do not change it.

Known trade-off: if upstream A accepted a mail but the final confirmation was lost,
upstream B is still tried and the recipient may get a duplicate. Without a queue this
cannot be ruled out.

## Soft quota

```yaml
upstreams:
  - name: smtp2go
    quota: { limit: 1000, window: 24h }
state:
  file: /var/lib/smtp-relay/state.json
```

Counts successfully delivered **messages** (one per mail, regardless of recipients) in
a sliding window, and exposes the percentage in `/metrics`. It is **soft**: going over
the limit never blocks mail; it only shows in metrics and logs a warning at 80% and
100%. Counters are saved to `state.file`, so they survive restarts (a hard crash can
lose up to about 10 seconds of counts). Run one instance per state file. The figure is
the relay's own estimate; mail sent through the same account from elsewhere is not
counted.

## Logging

Choose exactly one output (`stdout`, `stderr`, or `file` with rotation) and one format
(`text` or `json`).

Every mail that reaches the `DATA` stage produces **one summary line**:

```
INF mail from=alerts@example.com to=[ops@example.com] subj="Disk usage 91% on db01" status=delivered upstream=ses-eu attempts=1 size=2048 duration_ms=420 peer=192.168.1.20 uuid=3f1c...
ERR mail from=alerts@example.com to=[ops@example.com] subj="Backup failed" status=failed attempts=2 size=1530 duration_ms=30210 peer=192.168.1.20 uuid=9ab2... error="smtp2go: 535 authentication failed"
```

```json
{"level":"info","message":"mail","from":"alerts@example.com","to":["ops@example.com"],"subj":"Disk usage 91% on db01","status":"delivered","upstream":"ses-eu","attempts":1,"size":2048,"duration_ms":420,"peer":"192.168.1.20","uuid":"3f1c..."}
```

- Each failed attempt on an upstream is logged separately as a warning.
- Mails refused before `DATA` (wrong network or sender) are logged as warnings and
  have no summary line.
- `Subject` is decoded (RFC 2047), stripped of control characters so it cannot forge
  log lines, and cut at 200 characters.
- **Privacy:** `Subject` is the only mail header that is logged, and it can contain
  sensitive text (one-time codes, customer names). Message bodies and other headers
  are never logged, and neither are passwords.

## Metrics

Disabled by default. When enabled, serves Prometheus metrics, `/healthz` (process is
up) and `/readyz` (listeners are accepting) on `metrics.listen`. It binds to loopback
by default and has no authentication; do not expose it to untrusted networks.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `smtp_relay_messages_received_total` | counter | `result`, `reason` | Mails received: delivered, rejected, failed |
| `smtp_relay_upstream_deliveries_total` | counter | `upstream`, `result`, `error_class` | Delivery attempts per upstream |
| `smtp_relay_upstream_delivery_duration_seconds` | histogram | `upstream` | Time per attempt |
| `smtp_relay_upstream_last_success_timestamp_seconds` | gauge | `upstream` | Last successful delivery |
| `smtp_relay_upstream_failover_total` | counter | `from`, `to` | Times a mail moved to the next upstream |
| `smtp_relay_upstream_quota_used_percent` | gauge | `upstream` | Quota used (can exceed 100) |
| `smtp_relay_upstream_quota_used` / `_limit` | gauge | `upstream` | Messages used / configured limit |
| `smtp_relay_connections_total` | counter | `listener`, `result` | Accepted, denied by network, over limit |
| `smtp_relay_connections_active` | gauge | `listener` | Open connections |
| `smtp_relay_message_size_bytes` | histogram | – | Message sizes |
| `smtp_relay_tls_certificate_expiry_timestamp_seconds` | gauge | `cert` | Certificate expiry |
| `smtp_relay_quota_state_write_errors_total` | counter | – | Failed state file writes |
| `smtp_relay_build_info` | gauge | `version` | Running version |

Labels are limited to a small fixed set; email addresses, subjects and client IPs are
never used as labels. Go runtime and process metrics are included.

Example alerts:

```yaml
groups:
  - name: smtp-relay
    rules:
      - alert: SmtpRelayUpstreamFailing
        expr: sum by (upstream) (rate(smtp_relay_upstream_deliveries_total{result="failure"}[5m])) > 0
        for: 10m
      - alert: SmtpRelayUpstreamAuthError
        expr: increase(smtp_relay_upstream_deliveries_total{error_class="auth"}[15m]) > 0
      - alert: SmtpRelayQuotaHigh
        expr: smtp_relay_upstream_quota_used_percent > 80
        for: 5m
      - alert: SmtpRelayCertExpiring
        expr: smtp_relay_tls_certificate_expiry_timestamp_seconds - time() < 14 * 86400
```

## Security

**Read this before exposing the relay.**

- **Clients are not authenticated.** The only gate is `access.allowed_networks`, plus
  the sender allow-list. Keep `allowed_networks` as narrow as you can and add a
  firewall rule. An empty list or `0.0.0.0/0` turns the relay into an **open relay**
  that anyone can use to send spam through your provider account; the relay warns
  loudly at startup if you do this.
- **Default is loopback only** (`127.0.0.0/8`, `::1/128`).
- Plain-text SMTP inside your LAN is readable on that LAN. If that matters, use a
  `starttls` or `tls` listener with your own certificate; clients must support it.
- **Docker and NAT:** with Docker Desktop, Colima or the userland proxy, the relay
  sees the Docker gateway address instead of the real client IP, so
  `allowed_networks` cannot tell clients apart. Restrict who can reach the published
  port with the host firewall, or publish on a single LAN address. On Linux with
  standard iptables forwarding the real source address is preserved.
- Provider credentials are read from environment variables or files, kept in memory
  in a type that never prints itself, and never logged.
- The Docker image runs as a non-root user (UID 10001) with a read-only root
  filesystem and all capabilities dropped.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Provider notes

> Check each provider's current documentation; limits and rules change.

Because the relay does not rewrite the sender, **the From address your clients use
must be accepted by the provider.**

- **Amazon SES:** the sender must belong to a verified identity (address or domain).
  Use the SMTP credentials generated in the SES console, not raw IAM keys. Host
  `email-smtp.<region>.amazonaws.com`, port 587 with `starttls` (or 465 with `tls`).
  List your verified identities in `allowed_senders` / `allowed_sender_domains`.
- **Google (Gmail / Workspace):** `smtp.gmail.com`, port 587 `starttls` or 465 `tls`,
  with an App Password (requires 2-step verification). Gmail may replace the From
  address with the account's own unless the address is set up as a "Send mail as"
  alias. That is Google's behaviour, not the relay's.
- **SMTP2GO:** `mail.smtp2go.com`, ports 587, 2525 or 8025 with `starttls`, or 465
  with `tls`. A verified sender or domain is normally required.

When an upstream refuses a sender, the relay fails over to the next upstream, which
may have different rules.

## Development

```sh
go build ./...
go vet ./...
go test ./... -race
govulncheck ./...
```

Layout:

```
cmd/smtp-relay/      entry point
internal/config/     YAML loading, ${ENV} and *_file, validation, Secret type
internal/server/     listeners, TLS profiles, access policy, SMTP session
internal/upstream/   TLS connection, authentication, sending, error classes
internal/relay/      failover across upstreams
internal/app/        wiring and lifecycle
internal/quota/      sliding-window counters and state file
internal/maillog/    Subject extraction and the per-mail summary line
internal/logging/    zerolog setup, output and rotation
internal/metrics/    Prometheus metrics and health endpoints
```

The design lives in [`spec.md`](spec.md), the technical plan in
[`tasks/plan.md`](tasks/plan.md) and the task list in [`tasks/todo.md`](tasks/todo.md).

## License

[MIT](LICENSE)
