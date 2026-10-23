# Security Policy

## Supported versions

`smtp-relay` is pre-1.0. Only the latest release (or the `main` branch before the
first release) is supported.

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security tab, "Report a vulnerability"). Do not open a public
issue for security problems.

Useful details to include:

- a description of the issue and its impact
- steps to reproduce (a minimal configuration helps)
- affected versions
- any mitigation you know of

## Scope

`smtp-relay` intentionally does **not** authenticate the clients that send it mail;
access is limited by `access.allowed_networks` and the sender allow-list. Reaching the
relay from an allowed network and sending mail is therefore expected behaviour, not a
vulnerability. Likewise, the metrics endpoint has no authentication by design and binds
to loopback by default, and a deployment with an empty or `0.0.0.0/0` `allowed_networks`
is an open relay that the relay warns about at startup.

In scope:

- bypassing the network check (`allowed_networks`) or the sender check
  (`allowed_senders`, `allowed_sender_domains`, null sender)
- upstream credentials sent over an unencrypted connection without `allow_insecure_auth`,
  or upstream certificates accepted without `insecure_skip_verify`
- secrets (passwords, `*_file` contents) appearing in logs, metrics, error messages or
  SMTP replies
- log injection through mail content (for example a crafted `Subject` or address)
- the relay modifying a message beyond the documented line-ending normalisation
- a crash, hang or unbounded resource use triggered by a remote SMTP client
- the container image running with more privilege than documented (non-root UID 10001)

Out of scope: weaknesses of the upstream provider, of a TLS certificate or key you
supply, of the host firewall, or of Docker networking (see "Docker and NAT" in the
[README](README.md#docker-and-nat)).
