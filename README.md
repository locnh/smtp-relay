# smtp-relay

A small SMTP relay for your local network.

Point your services at `smtp-relay` and forget about SMTP credentials. The relay
holds the credentials and handles **TLS and authentication** towards a real SMTP
server (Gmail / Google Workspace, Amazon SES, SMTP2GO, Mailgun, ...). Your cron
jobs, printers, scripts and apps only need the relay's `host:port`: no username,
no password, no TLS settings.

> **Status:** implemented, pre-1.0. The behaviour described here is checked against the
> code and the test suite, and the log and metrics samples below come from a real run.
> It has **not yet been tried against a real provider** (Gmail, SES, SMTP2GO), and the
> Docker image has not been published yet. See [Provider notes](#provider-notes).

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
  accepts them and talks modern TLS upstream (TLS 1.2 or newer).
- Several upstreams in priority order, so one provider outage does not lose mail.
- One log line per mail, plus metrics, so you can see whether mail is getting out.

## Features

- Accepts SMTP on any number of listeners: plain, STARTTLS, or implicit TLS; IPv4 and IPv6.
- Forwards to real SMTP servers over TLS with `PLAIN` / `LOGIN` authentication.
- **Failover** across upstreams, in the order you list them.
- **Access control** by source network, and by sender address or domain.
- **Messages are forwarded unchanged**: envelope, headers and body are not modified.
- One **summary log line per mail** (`from`, `to`, `status`, ...), text or JSON. Message
  content, including the `Subject`, is never logged.
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
- **No message rewriting**: no `Received` header is added, no `From` change, no DKIM
  signing. The only change is protocol-level, see [Forwarded unchanged](#forwarded-unchanged).
- No recipient filtering, no aliases, no local delivery. It is not an MTA.
- No hot reload: a configuration change needs a restart.
- Not a bulk-mail or newsletter engine. Every mail opens a new upstream connection.

## Install

### Binary

Requires Go 1.27 or newer. Build from a checkout:

```sh
go build -o smtp-relay ./cmd/smtp-relay
./smtp-relay -version
```

A release build with a version string:

```sh
go build -trimpath \
  -ldflags "-s -w -X main.version=0.1.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o smtp-relay ./cmd/smtp-relay
```

Tagged releases are meant to be built by [`release.yml`](.github/workflows/release.yml)
(Linux amd64 and arm64 tarballs). No release has been tagged yet.

### Docker

```sh
docker build -t smtp-relay .
# with a version string:
docker build --build-arg VERSION=0.1.0 -t smtp-relay:0.1.0 .
```

The release workflow is set up to push images to `ghcr.io/locnh/smtp-relay` for tagged
versions. None exists yet, so build locally for now.

## Quick start

### Binary

1. Write a minimal `config.yaml`. This one listens on the unprivileged port 2525 and
   accepts mail from this machine only (the default `allowed_networks`):

   ```yaml
   server:
     hostname: relay.home.lan
     listen:
       - address: "127.0.0.1:2525"

   access:
     allowed_sender_domains: [example.com]

   upstreams:
     - name: primary
       host: smtp.example.com
       tls: starttls
       auth:
         username: ${SMTP_USER}
         password: ${SMTP_PASS}
   ```

2. Export the credentials the config refers to:

   ```sh
   export SMTP_USER=your-smtp-username
   export SMTP_PASS=your-smtp-password
   ```

3. Check it, then run:

   ```sh
   ./smtp-relay -config config.yaml -check-config
   ./smtp-relay -config config.yaml
   ```

   `-check-config` validates the file and exits (`config OK`). It does not connect to
   the upstream, so it cannot tell you the credentials are right.

For a fuller setup start from [`config.example.yaml`](config.example.yaml): it needs
all four `SES_SMTP_*` / `SMTP2GO_*` variables set (or remove the upstreams you do not
use), and its `state.file` directory must be creatable and writable by the user
running the relay (`/var/lib/smtp-relay` by default).

### Docker Compose

```sh
cp config.docker.example.yaml config.yaml    # edit upstreams, allowed_networks, hostname
cat > .env <<'EOF'
UPSTREAM1_USER=your-smtp-username
UPSTREAM1_PASS=your-smtp-password
EOF

docker compose run --rm smtp-relay -config /etc/smtp-relay/config.yaml -check-config
docker compose up -d
docker compose ps        # STATUS should become "healthy"
docker compose logs -f
```

The container listens on port **2525** (a non-root process cannot bind port 25) and
Compose publishes it as host port **25** on all interfaces. Edit the `ports:` entry to
change that, or to bind a single LAN address, for example `"192.168.1.10:25:2525"`.
**Read [Docker and NAT](#docker-and-nat) before exposing it.**

Things to know about the Compose setup:

- `.env` and `config.yaml` are git-ignored. Keep them out of version control.
- Logs go to stdout (`docker compose logs`). Keep `logging.output: stdout`: the root
  filesystem is read-only, so a log file would have nowhere to go.
- Quota counters live in the named volume `state`, mounted at `/var/lib/smtp-relay`
  and writable by the container user (UID 10001).
- The healthcheck calls `http://127.0.0.1:9090/healthz` inside the container, so it
  needs `metrics.enabled: true` and `metrics.listen: "0.0.0.0:9090"`, as in
  `config.docker.example.yaml`. Without metrics the container is reported unhealthy.
- `docker compose stop` waits up to `stop_grace_period` (50s) for a clean shutdown.
- Set `server.hostname` explicitly. The default is the container's hostname, which is
  a random ID, and it is also the name the relay announces to your upstreams.

### Send a test mail

The sender's domain must be allowed by `access.allowed_*`; the examples use
`example.com`. Use the port you published (2525 in the binary quick start, 25 for
Docker Compose).

```sh
# curl
printf 'From: noreply@example.com\r\nTo: you@example.org\r\nSubject: relay test\r\n\r\nhello\r\n' |
  curl --url smtp://127.0.0.1:2525 --mail-from noreply@example.com \
       --mail-rcpt you@example.org --upload-file -

# swaks (https://www.jetmore.org/john/code/swaks/), if installed
swaks --server 127.0.0.1 --port 2525 --from noreply@example.com --to you@example.org \
      --header "Subject: relay test" --body "hello"

# python3
python3 - <<'EOF'
import smtplib
msg = b"From: noreply@example.com\r\nTo: you@example.org\r\nSubject: relay test\r\n\r\nhello\r\n"
with smtplib.SMTP("127.0.0.1", 2525) as s:
    s.sendmail("noreply@example.com", ["you@example.org"], msg)
EOF
```

You should see one summary line in the relay's log (see [Logging](#logging)).

## Configuring your services

Point them at the relay with **no authentication and no encryption**:

| Setting | Value |
|---|---|
| SMTP server / host | the relay's IP or name |
| Port | `25` (or whatever you published) |
| Encryption / TLS | none |
| Username / password | none |
| From address | one allowed by `access.allowed_senders` / `allowed_sender_domains` |

The relay does not advertise `AUTH`. A client that insists on authenticating (some
libraries fail when `AUTH` is missing) needs its authentication turned off.

Examples:

```ini
# msmtp (~/.msmtprc or /etc/msmtprc)
account default
host relay.home.lan
port 25
from alerts@example.com
auth off
tls off
```

```sh
# cron: send job output through msmtp. With msmtp installed as sendmail,
# cron's MAILTO works as usual.
MAILTO=ops@example.com
```

Printers and scanners: enter the relay as the SMTP server, leave authentication and
SSL/TLS off, and use an allowed sender address.

> The From address must be accepted by your **upstream provider** too, because the
> relay does not change it. See [Provider notes](#provider-notes).

## Configuration

Everything is in one YAML file, passed with `-config`. See
[`config.example.yaml`](config.example.yaml) (binary) and
[`config.docker.example.yaml`](config.docker.example.yaml) (Docker) for complete,
commented examples.

```sh
smtp-relay -config config.yaml -check-config   # validate and exit
smtp-relay -config config.yaml                 # run
smtp-relay -version                            # prints: smtp-relay/<version> (<build time>)
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | `-version`, `-help`, `-check-config` passed, or a clean shutdown |
| `1` | invalid configuration (all errors are printed), a startup failure such as a port already in use, or in-flight mail not finished within `server.timeouts.shutdown` |
| `2` | usage error: unknown flag, missing `-config`, or an extra argument |

Rules:

- **Strict:** an unknown key is an error, so typos do not pass silently.
- **`${NAME}`** is replaced by the environment variable `NAME`. A bare `$NAME` is left
  alone. An unset variable is an error.
- Every secret has a `*_file` form (`password_file`) for Docker/Kubernetes secrets; one
  trailing newline is removed. Set one or the other, not both.
- Durations use Go syntax: `30s`, `5m`, `24h`. Sizes are plain byte counts.
- All errors are reported together, with the path of the offending key, for example
  `upstreams[1].auth.password`. Secret values are never printed.
- Configuration problems exit before any port is opened.
- Warnings (do not stop startup): an empty `allowed_networks` or a `/0` network
  (open relay), `insecure_skip_verify: true`, an unknown `logging.level` (falls back
  to `info`). `-check-config` prints them as `warning: ...`; a normal start logs them.

### Keys and defaults

| Key | Default | Notes |
|---|---|---|
| `server.hostname` | system hostname | Name in the `220` banner and in `EHLO` towards upstreams. Use a real FQDN |
| `server.welcome_message` | empty | Appended to the hostname in the greeting: `220 <hostname> <message> ESMTP Service Ready` |
| `server.listen[]` | `127.0.0.1:25`, `tls: none` | Each entry: `address` (`host:port`, IPv4 or `[::1]:port`), `tls` (`none` / `starttls` / `tls`), `force_tls` (starttls only) |
| `server.tls.cert_file`, `key_file` | – | Required when a listener uses `starttls` or `tls` |
| `server.tls.profile` | `default` | `default` (Go defaults), `modern` (TLS 1.3+), `intermediate` (TLS 1.2+, ECDHE + AEAD ciphers), `legacy` (TLS 1.0+, weak ciphers: only if a device needs it) |
| `server.timeouts.read`, `write` | `60s` | Per SMTP command |
| `server.timeouts.data` | `5m` | Whole DATA phase; a stalled client gets `421 4.4.2` and is disconnected |
| `server.timeouts.shutdown` | `30s` | Max wait for in-flight mail on SIGINT/SIGTERM |
| `server.limits.max_connections` | `100` | Shared by all listeners; `-1` = unlimited |
| `server.limits.max_message_size` | `10240000` | Bytes |
| `server.limits.max_recipients` | `100` | |
| `server.limits.max_line_length` | `1048576` | Bytes, minimum `1000` (RFC 5321). Longest single line, for commands and for `DATA` lines; a longer line gets `451 4.3.0` and the connection is closed |
| `access.allowed_networks` | `127.0.0.0/8`, `::1/128` | CIDRs without host bits. An explicit empty list means "everyone" (warning) |
| `access.allowed_senders` | empty | Exact `MAIL FROM` addresses |
| `access.allowed_sender_domains` | empty | Exact domain of `MAIL FROM`, no subdomains |
| `upstreams[].name` | required | Unique, `[a-z0-9_-]+`; label in logs and metrics |
| `upstreams[].host` | required | |
| `upstreams[].port` | by `tls`: `starttls` 587, `tls` 465, `none` 25 | |
| `upstreams[].tls` | `starttls` | `starttls` / `tls` / `none` |
| `upstreams[].auth.mechanism` | `auto` | `auto` / `plain` / `login`. `username`, and `password` or `password_file`, are required when `auth` is set |
| `upstreams[].auth.allow_insecure_auth` | `false` | Needed to use `auth` together with `tls: none` |
| `upstreams[].tls_options` | verify on, system CAs | `insecure_skip_verify`, `ca_file`, `client_cert_file` + `client_key_file` (mutual TLS: both or neither) |
| `upstreams[].timeouts` | `connect` 10s, `command` 30s, `data` 2m | Each at least 1s |
| `upstreams[].quota` | none | `limit` (messages, > 0) and `window` (default `24h`, at least `1m`). Needs `state.file` |
| `state.file` | none | Quota counters. Its directory must be creatable and writable |
| `logging.level` | `info` | `trace` / `debug` / `info` / `warn` / `error` |
| `logging.format` | `text` | `text` / `json` |
| `logging.output` | `stdout` | `stdout` / `stderr` / `file` (exactly one) |
| `logging.file` | `max_size_mb` 10, `max_backups` 3, `max_age_days` 30, `compress` true | Used with `output: file`; `path` is required. Files are created with mode 0640 |
| `metrics.enabled` | `false` | |
| `metrics.listen` | `127.0.0.1:9090` | Also serves `/healthz` and `/readyz` |
| `metrics.path` | `/metrics` | Must start with `/` |

A TLS listener example (certificate and key are yours; none ships with the repo):

```yaml
server:
  listen:
    - address: "0.0.0.0:25"
    - address: "0.0.0.0:587"
      tls: starttls
      force_tls: true      # refuse MAIL FROM (530 5.7.0) until the client upgrades
    - address: "0.0.0.0:465"
      tls: tls
  tls:
    cert_file: /etc/smtp-relay/tls.crt
    key_file: /etc/smtp-relay/tls.key
    profile: intermediate
```

### Upstream TLS modes

| `tls` | Behaviour |
|---|---|
| `starttls` | Connect, then **require** STARTTLS. If the server does not offer it, the attempt fails and nothing is sent (credentials included). Usually port 587. |
| `tls` | TLS from the first byte (implicit TLS). Usually port 465. |
| `none` | No encryption. Development or a trusted internal hop only. |

- Certificates are verified by default, with TLS 1.2 as the minimum.
  `insecure_skip_verify: true` turns verification off and logs a warning at startup.
- Credentials are **never sent over an unencrypted connection**, for `PLAIN` and
  `LOGIN` alike, unless you set `allow_insecure_auth: true`.
- `mechanism: auto` uses `PLAIN` when the server offers it and `LOGIN` otherwise. A
  fixed mechanism the server does not advertise is an `auth` failure and nothing is sent.
- If `auth` is configured but the server advertises no `AUTH`, the attempt fails.
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

- A connection from outside `allowed_networks` gets `554 5.7.1 Access denied` and is
  closed. The default is loopback only.
- A `MAIL FROM` must match `allowed_senders` (exact address) **or**
  `allowed_sender_domains` (exact domain, subdomains do not match). If both lists
  are empty, any sender is accepted. Otherwise a sender that matches neither gets
  `550 5.7.1 Sender address not allowed`.
- Matching is case-insensitive. The null sender `<>` is always rejected (same `550`).
- Recipients are not filtered.
- Past `max_connections` a new connection gets `421 4.7.0 Too many connections`.
  Past `max_recipients` the extra `RCPT TO` gets `452 4.5.3`; the mail can still go
  out with the recipients accepted so far.

### What a client sees

The relay greets with `220 <hostname> [<welcome_message>] ESMTP Service Ready` and
advertises `PIPELINING`, `8BITMIME`, `ENHANCEDSTATUSCODES`, `CHUNKING`, `SMTPUTF8`,
`SIZE` and `LIMITS`, plus `STARTTLS` on `starttls` listeners. It never advertises `AUTH`.

`CHUNKING` (BDAT) is always advertised by the SMTP library; the DATA timeout still
applies to it, but a message refused for size through BDAT is not counted in the
`size_exceeded` metric.

Lines up to `server.limits.max_line_length` (1 MiB by default) are accepted, so a
hand-made message with one very long line, an HTML mail or a pasted log still goes
through. A longer line is refused with `451 4.3.0 Error reading message` and the
connection is closed.

### Forwarded unchanged

MAIL FROM, RCPT TO, headers and body go to the upstream exactly as the client sent
them: no header is added or removed, and **no `Received` header is added**. This
differs from RFC 5321 §4.4 on purpose, so internal IPs and host names are not leaked to
recipients. Tracing is done with the log (`peer`, `uuid`).

The one protocol-level exception: line endings are normalised to CRLF and dot-stuffing
is re-applied when the message is sent, so a client that sends a bare LF has it turned
into CRLF. Clients that follow the RFC are not affected.

## Failover

Upstreams are tried **in the order listed**. The first success ends the attempt, so a
mail is delivered once. On any failure (connection, TLS, authentication, timeout, 4xx
or 5xx) the relay logs a warning and moves to the next one. If all fail, the client
gets the error from the last upstream: SMTP errors keep their code and message text,
other failures become `421 4.4.0 Forwarding failed`. Details such as upstream host names
only go to the log.

The order is fixed; quota, latency or past failures do not change it. A permanent
5xx (for example an unknown recipient) is also tried on the next upstream.

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
a sliding window of one-minute buckets, and exposes the percentage in `/metrics`. It is
**soft**: going over the limit never blocks mail; it only shows in metrics and logs a
warning once at 80% and once at 100%.

- Counters are written atomically to `state.file` (mode 0600) at most every 10 seconds
  and on shutdown, so they survive a clean restart. A hard crash or SIGKILL can lose up
  to about 10 seconds of counts.
- A corrupt state file is renamed to `<file>.corrupt-<timestamp>` and the relay starts
  with empty counters.
- If the file cannot be written while running, the relay logs an error, increments
  `smtp_relay_quota_state_write_errors_total` and keeps delivering.
- Changing `limit` takes effect at once. A longer `window` starts low until the history
  fills up. Upstreams removed from the config are dropped from the file.
- Run **one instance per state file**; there is no locking.
- The figure is the relay's own estimate; mail sent through the same account from
  elsewhere is not counted.

## Logging

Choose exactly one output (`stdout`, `stderr`, or `file` with rotation) and one format
(`text` or `json`).

Every mail that reaches the end of `DATA` produces **one summary line**. These are real
lines from a local test run (the client ran on the same machine, hence `peer=127.0.0.1`;
`ses-eu` was reachable, `smtp2go` was a stand-in server). `text`:

```
2026-10-23T08:58:04+02:00 WRN upstream failed upstream=ses-eu uuid=197a604d-dab5-4370-a471-904e6ce7a15a error="connect: dial tcp 127.0.0.1:25299: connect: connection refused" error_class=connect
2026-10-23T08:58:04+02:00 INF mail from=alerts@example.com to=["ops@example.org"] status=delivered upstream=smtp2go attempts=2 size=85 duration_ms=13 peer=127.0.0.1 uuid=197a604d-dab5-4370-a471-904e6ce7a15a
2026-10-23T08:58:04+02:00 WRN upstream failed upstream=ses-eu uuid=7d6ae07c-328c-4435-8c7d-601d31487979 error="connect: dial tcp 127.0.0.1:25299: connect: connection refused" error_class=connect
2026-10-23T08:58:04+02:00 WRN upstream failed upstream=smtp2go uuid=7d6ae07c-328c-4435-8c7d-601d31487979 error="smtp_5xx: smtp 550: 5.1.1 no such user" error_class=smtp_5xx
2026-10-23T08:58:04+02:00 ERR mail from=alerts@example.com to=["user@bad.test"] status=failed attempts=2 size=77 duration_ms=2 peer=127.0.0.1 uuid=7d6ae07c-328c-4435-8c7d-601d31487979 error="smtp_5xx: smtp 550: 5.1.1 no such user"
```

`json` (one object per line):

```json
{"level":"info","from":"alerts@example.com","to":["ops@example.org"],"status":"delivered","upstream":"smtp2go","attempts":2,"size":85,"duration_ms":14,"peer":"127.0.0.1","uuid":"84088e93-651b-42a8-88fc-d473e9e226cf","time":"2026-10-23T08:58:06+02:00","message":"mail"}
{"level":"error","from":"alerts@example.com","to":["user@bad.test"],"status":"failed","attempts":2,"size":77,"duration_ms":3,"peer":"127.0.0.1","uuid":"ef6e9f61-5327-4bb8-a62b-c1c5436d2fc4","error":"smtp_5xx: smtp 550: 5.1.1 no such user","time":"2026-10-23T08:58:06+02:00","message":"mail"}
```

Fields of the summary line:

| Field | Meaning |
|---|---|
| `from`, `to` | Envelope sender and recipients (at most 10 shown; `rcpt_count` carries the total when cut) |
| `status` | `delivered` (level info) or `failed` (level error) |
| `upstream` | The upstream that accepted it (only when delivered) |
| `attempts` | Number of upstreams tried |
| `size` | Size of the DATA payload in bytes |
| `duration_ms` | Time spent on `DATA`: reading the message plus all upstream attempts |
| `peer` | Client IP |
| `uuid` | Mail ID; the same ID appears on every `upstream failed` line of that mail |
| `error` | Last error (only when failed) |

Other lines you will see:

- `INF listening` per listener and `INF started` at startup; `INF shutting down` and
  `INF stopped` at the end.
- `WRN upstream failed` for each failed attempt, with `upstream`, `uuid`,
  `error_class` and `error`.
- `WRN sender rejected` (`peer`, `sender_address`, `reason`) and
  `WRN connection denied: network not allowed` (`peer`) for mail refused before `DATA`.
  These have no summary line.
- `WRN upstream quota reached 80%` / `100%`.
- Step-by-step detail (accepted attempts, read failures) at `debug`.

Notes:

- **Privacy:** no part of the message is logged: not the body and not any header,
  `Subject` included, because subjects often carry one-time codes or customer names.
  Only the envelope (`from`, `to`), sizes, timing and the outcome are recorded, and
  never passwords. Addresses and errors are stripped of control characters so they
  cannot forge log lines. To trace one mail, search the logs for its `uuid`.
- The text format has no colours and uses RFC 3339 timestamps.

## Metrics

Disabled by default. When enabled, serves Prometheus metrics at `metrics.path`,
`/healthz` (process is up) and `/readyz` (listeners are accepting; `503` before the SMTP
listeners are bound and during shutdown; it does not call any upstream) on
`metrics.listen`. It binds to loopback by default and has no authentication; do not
expose it to untrusted networks. If the metrics port is busy the relay refuses to start.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `smtp_relay_messages_received_total` | counter | `result` (`delivered` / `rejected` / `failed`), `reason` | `reason` is empty for delivered; `sender_denied`, `null_sender`, `size_exceeded` for rejected; `upstream_error` for failed |
| `smtp_relay_upstream_deliveries_total` | counter | `upstream`, `result` (`success` / `failure`), `error_class` | Delivery attempts per upstream. `error_class`: `none`, `connect`, `tls`, `auth`, `timeout`, `smtp_4xx`, `smtp_5xx`, `other` |
| `smtp_relay_upstream_delivery_duration_seconds` | histogram | `upstream` | Time per attempt |
| `smtp_relay_upstream_last_success_timestamp_seconds` | gauge | `upstream` | Unix time of the last success |
| `smtp_relay_upstream_failover_total` | counter | `from`, `to` | Times a mail moved from one upstream to the next |
| `smtp_relay_upstream_quota_used_percent` | gauge | `upstream` | Quota used (can exceed 100); only upstreams with a `quota` |
| `smtp_relay_upstream_quota_used` | gauge | `upstream` | Messages counted in the window |
| `smtp_relay_upstream_quota_limit` | gauge | `upstream` | Configured limit |
| `smtp_relay_quota_state_write_errors_total` | counter | – | Failed state file writes (present when any upstream has a quota) |
| `smtp_relay_connections_total` | counter | `listener`, `result` (`accepted` / `denied_network` / `rejected_limit`) | Client connections |
| `smtp_relay_connections_active` | gauge | `listener` | Open connections |
| `smtp_relay_message_size_bytes` | histogram | – | Sizes of received messages |
| `smtp_relay_tls_certificate_expiry_timestamp_seconds` | gauge | `cert` (`server`, `upstream:<name>`) | Expiry of the server certificate and of upstream client certificates, when configured |
| `smtp_relay_build_info` | gauge | `version` | Running version, always 1 |

Go runtime and process metrics are included. Labels come from a small fixed set or from
your configured names; email addresses, client IPs and message content are never used as
labels. `listener` is the configured `address` (for example `0.0.0.0:2525`).

A real excerpt from the same test run as the log lines above (counters and gauges only):

```
smtp_relay_messages_received_total{reason="",result="delivered"} 2
smtp_relay_messages_received_total{reason="sender_denied",result="rejected"} 1
smtp_relay_messages_received_total{reason="upstream_error",result="failed"} 1
smtp_relay_upstream_deliveries_total{error_class="connect",result="failure",upstream="ses-eu"} 2
smtp_relay_upstream_deliveries_total{error_class="none",result="success",upstream="ses-eu"} 1
smtp_relay_upstream_deliveries_total{error_class="none",result="success",upstream="smtp2go"} 1
smtp_relay_upstream_deliveries_total{error_class="smtp_5xx",result="failure",upstream="smtp2go"} 1
smtp_relay_upstream_failover_total{from="ses-eu",to="smtp2go"} 2
smtp_relay_upstream_quota_limit{upstream="smtp2go"} 1000
smtp_relay_upstream_quota_used{upstream="smtp2go"} 1
smtp_relay_upstream_quota_used_percent{upstream="smtp2go"} 0.1
smtp_relay_connections_total{listener="127.0.0.1:2525",result="accepted"} 4
smtp_relay_build_info{version="dev"} 1
```

Example alert rules (adjust thresholds to your traffic):

```yaml
groups:
  - name: smtp-relay
    rules:
      - alert: SmtpRelayUpstreamFailing
        expr: |
          sum by (upstream) (rate(smtp_relay_upstream_deliveries_total{result="failure"}[5m]))
            / sum by (upstream) (rate(smtp_relay_upstream_deliveries_total[5m])) > 0.05
        for: 10m
      - alert: SmtpRelayUpstreamAuthError
        expr: increase(smtp_relay_upstream_deliveries_total{error_class="auth"}[15m]) > 0
      - alert: SmtpRelayFailover
        expr: increase(smtp_relay_upstream_failover_total[15m]) > 0
      - alert: SmtpRelayQuotaHigh
        expr: smtp_relay_upstream_quota_used_percent > 80
        for: 5m
      - alert: SmtpRelayStateWriteErrors
        expr: increase(smtp_relay_quota_state_write_errors_total[15m]) > 0
      - alert: SmtpRelayDeniedConnections
        expr: increase(smtp_relay_connections_total{result="denied_network"}[15m]) > 0
      - alert: SmtpRelayCertExpiring
        expr: smtp_relay_tls_certificate_expiry_timestamp_seconds - time() < 14 * 86400
```

## Operations

- **Start-up order:** configuration is loaded and validated, then the logger, the quota
  state, the metrics port and finally the SMTP listeners are opened. A port that is
  already in use stops the start with exit code 1.
- **Shutdown:** on `SIGINT` or `SIGTERM` the relay stops accepting, closes idle
  connections, waits for mails already being processed for up to
  `server.timeouts.shutdown`, then saves the quota state, flushes the log and stops
  the metrics server. If mail is still running when the time is up, it is cut off,
  the relay exits with code 1 and the affected clients see a failed connection and
  retry. A **second** `SIGINT`/`SIGTERM` during a slow shutdown ends the process
  immediately.
- **Worst case for a clean stop** is `server.timeouts.shutdown` plus about 5 s for
  cut-off deliveries to unwind plus up to 5 s for the metrics server. In Docker keep
  `stop_grace_period` (50s in the compose file) at least 20 s above
  `server.timeouts.shutdown`.
- **Memory:** a mail is held entirely in memory until it is delivered (needed for
  failover). The worst case is `max_message_size` × `max_connections`: about 1 GB at the
  defaults (10 240 000 bytes × 100), plus buffer overhead. On a small host lower
  `max_connections` or `max_message_size`.
  `max_line_length` adds a second bound: while a connection is reading a command or a
  line it buffers at most that many bytes, so under attack the extra worst case is
  `max_line_length` × `max_connections` (1 MiB × 100 = about 100 MB at the defaults).
  A legitimate message is limited by `max_message_size`, not by this key, which only
  needs to be larger than the longest line your clients send.
- **Upstream timeouts:** each mail opens a fresh connection; `connect` bounds the TCP
  and TLS handshake, `command` each SMTP command, `data` the transfer of the message.
  When several upstreams fail slowly these add up, so a client may wait for the sum of
  their timeouts before it gets an answer; set the client's own timeout accordingly.

## Security

**Read this before exposing the relay.**

- **Clients are not authenticated.** The only gate is `access.allowed_networks`, plus
  the sender allow-list. Keep `allowed_networks` as narrow as you can and add a
  firewall rule. An empty list or `0.0.0.0/0` turns the relay into an **open relay**
  that anyone can use to send spam through your provider account; the relay warns
  at startup (and in `-check-config`) if you do this.
- **Default is loopback only** (`127.0.0.0/8`, `::1/128`), for both the SMTP listener
  and the metrics endpoint.
- Plain-text SMTP inside your LAN is readable on that LAN. If that matters, use a
  `starttls` or `tls` listener with your own certificate; clients must support it.
- **Sender allow-list:** set `allowed_senders` / `allowed_sender_domains` so a
  compromised or misconfigured device cannot send as arbitrary addresses. The relay
  does not rewrite the sender, so this is also what your provider will see.
- **Logs hold addresses, not content.** They list sender and recipient addresses and
  the outcome; message bodies and headers (`Subject` included) are never logged
  (see [Logging](#logging)).
- Upstream credentials are never sent unencrypted unless you set `allow_insecure_auth`,
  and certificates are verified unless you set `insecure_skip_verify`.

### Docker and NAT

With Docker Desktop, Colima or the userland proxy, the relay sees the Docker gateway
address instead of the real client IP, so `allowed_networks` cannot tell clients apart:
anything that can reach the published port looks like the gateway. Restrict who can
reach the port with the host firewall, or publish it on a single LAN address
(`"192.168.1.10:25:2525"`). On Linux with standard iptables forwarding the real source
address is normally preserved, but check that with a test from a second machine before
you rely on `allowed_networks`.

The compose file sets `read_only: true`, `cap_drop: ALL` and `no-new-privileges`, and
the image runs as UID 10001 with no login shell.

### Reporting

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Troubleshooting

Start with the log: every failed attempt has a `WRN upstream failed` line with the same
`uuid` as the summary line.

| Symptom | Likely cause and what to do |
|---|---|
| Client gets `550 5.7.1 Sender address not allowed` | The `MAIL FROM` is not in `allowed_senders` or `allowed_sender_domains` (the log line `sender rejected` shows `sender_address` and `reason`). Add it, or use an allowed address. `reason=null_sender` means a bounce-style `<>` sender, which is always refused |
| Client gets `554 5.7.1 Access denied` right after connecting | The client's IP is not in `access.allowed_networks` (log: `connection denied: network not allowed`, and `connections_total{result="denied_network"}`). In Docker the IP may be the gateway, see [Docker and NAT](#docker-and-nat) |
| Client gets `421 4.4.0 Forwarding failed` | Every upstream failed with a non-SMTP error. Check the `WRN upstream failed` lines and their `error_class`: `connect` (host, port, firewall, DNS), `tls` (certificate, STARTTLS not offered, TLS version), `auth` (wrong credentials, mechanism not offered, no TLS), `timeout` (raise the upstream `timeouts` or check the network), `other` |
| Client gets the upstream's own code, such as `550` or `554` | The upstream refused the mail (`smtp_5xx`) or asked to retry (`smtp_4xx`). Typical causes: sender not verified at the provider, unknown recipient, rate limit or quota at the provider |
| Client gets `421 4.7.0 Too many connections` | `server.limits.max_connections` reached; raise it or find the client that leaks connections (`smtp_relay_connections_active`) |
| Client gets `451 4.3.0 Error reading message` | A line longer than `server.limits.max_line_length`, or the connection broke during `DATA`. Run with `logging.level: debug` to see the reason |
| Client gets `552 5.3.4` or `452 4.5.3` | Message above `max_message_size`, or more than `max_recipients` recipients |
| Client gets `530 5.7.0 Must issue a STARTTLS command first` | The listener has `force_tls: true`; the client must use STARTTLS |
| Startup warning about an open relay | `allowed_networks` is empty or contains `0.0.0.0/0` / `::/0`. Narrow it |
| `docker compose ps` says `unhealthy` | The healthcheck needs `metrics.enabled: true` and `metrics.listen: "0.0.0.0:9090"` in `config.yaml`. Check `docker compose logs` for a start-up error |
| No data at `/metrics` | `metrics.enabled` is `false` by default; the default address is loopback only |
| `listen ...: bind: address already in use` or `permission denied` | Another process holds the port, or a non-root user is binding a port below 1024. Use a high port (as Docker does) or grant the capability |
| Quota counter is lower than expected after a crash | Counters are saved every 10 s; a hard crash can lose about 10 s of counts (a clean stop loses nothing) |
| Exit code 1 after `SIGTERM` | A mail did not finish within `server.timeouts.shutdown` and was cut off |
| Provider rejects your `EHLO` | `server.hostname` is not a valid FQDN (in Docker it defaults to the container ID). Set it |

## Provider notes

> These are **notes to verify against each provider's current documentation**. They have
> not been tested against real accounts yet (a manual test with a real provider is still
> to be done), and limits and rules change.

Because the relay does not rewrite the sender, **the From address your clients use
must be accepted by the provider.**

- **Amazon SES:** the sender must belong to a verified identity (address or domain).
  Use the SMTP credentials generated in the SES console, not raw IAM access keys. Host
  `email-smtp.<region>.amazonaws.com`, port 587 with `starttls` (or 465 with `tls`).
  List your verified identities in `allowed_senders` / `allowed_sender_domains`.
- **Google (Gmail / Workspace):** `smtp.gmail.com`, port 587 `starttls` or 465 `tls`,
  with an App Password (requires 2-step verification). OAuth is not supported. Gmail may
  replace the From address with the account's own unless the address is set up as a
  "Send mail as" alias. That is Google's behaviour, not the relay's.
- **SMTP2GO:** `mail.smtp2go.com`, ports 587, 2525 or 8025 with `starttls`, or 465
  with `tls`. A verified sender or domain is normally required.

When an upstream refuses a sender, the relay fails over to the next upstream, which
may have different rules.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .                      # prints nothing when everything is formatted
go test ./... -race -count=1
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

CI ([`ci.yml`](.github/workflows/ci.yml)) runs formatting, vet, build, tests with `-race`,
`govulncheck` and a Docker build.

Layout:

```
cmd/smtp-relay/      entry point: flags, signals, exit codes
internal/config/     YAML loading, ${ENV} and *_file, validation, Secret type
internal/server/     listeners, TLS profiles, access policy, SMTP session
internal/upstream/   TLS connection, authentication, sending, error classes
internal/relay/      failover across upstreams
internal/app/        wiring and lifecycle
internal/quota/      sliding-window counters and state file
internal/maillog/    the per-mail summary line and log-injection sanitising
internal/logging/    zerolog setup, output and rotation
internal/metrics/    Prometheus metrics and health endpoints
```

## License

[MIT](LICENSE)
