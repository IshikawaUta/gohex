# Security Policy

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories on this repository
(→ *Security* → *Report a vulnerability*), or email the maintainers. Please do not
open public issues for security bugs.

We aim to acknowledge within 72 hours and to publish a fix and credit (unless you
prefer anonymity) within a reasonable window.

## Supported versions

Only the latest release receives security fixes.

## Scope & explicit non-goals

GoHex is a defensive, forensic tool. The following are **out of scope and will not
be implemented**; requests for them will be declined:

- Disk wiping / secure erase of entire devices
- Live process memory editing, process injection, debugging live processes
- Bypassing passwords, disk/file encryption, DRM, or OS protections
- Anti-forensics: log deletion, timestamp manipulation, evidence destruction
- Credential extraction (LSASS, SAM, browser password vaults, keychains)
- Stealth behavior, rootkits, antivirus evasion

## Security design

- **Read-only by default.** Disk/partition writes require `--allow-unsafe-write`,
  a two-step confirmation dialog, and an audit-log entry (see `docs/security.md`).
- **No telemetry, no outbound network by default.** Update checks are opt-in.
- **No code execution** from files that are opened (parsers never `exec`).
- **Strict input validation** in all parsers; the parser suite is fuzz-tested in CI.
- **Optional AES-256-GCM encryption** for evidence containers and audit logs.
- Dependencies are scanned in CI (`govulncheck`, Dependabot, gitleaks).
- Release artifacts ship with checksums and signatures (cosign/sigstore).
