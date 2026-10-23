# Security Policy

## Supported versions

Only the latest release is supported.

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security tab, "Report a vulnerability"). Do not open a public
issue for security problems.

Useful details to include:

- a description of the issue and its impact
- steps to reproduce
- affected versions
- any mitigation you know of

## Scope notes

`smtp-relay` intentionally does **not** authenticate the clients that send it mail;
access is limited by `access.allowed_networks` and the sender allow-list. Reaching the
relay from an allowed network and sending mail is therefore expected behaviour, not a
vulnerability. Examples that **are** in scope: bypassing the network or sender checks,
credentials sent over an unencrypted connection without `allow_insecure_auth`, secrets
appearing in logs or metrics, log injection through mail content, or a crash or
resource exhaustion triggered by a remote client.
