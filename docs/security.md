# GoHex security model

This document describes the technical controls in GoHex. Vulnerability
reporting policy lives in [SECURITY.md](../SECURITY.md); legal/ethical scope
in [legal.md](legal.md).

## Threat model (Stage 1)

GoHex runs as a normal desktop process on the examiner's machine. It is
designed against:

1. **Accidental damage** to evidence — the #1 real-world risk. Mitigated by
   read-only defaults, profiles, sandbox mode, undo, and hash verification.
2. **Untrusted input files** — forensic images may be crafted. The parser
   surface is deliberately tiny: raw bytes, text codecs, Intel-HEX/S-records,
   patterns/regexps. All file reads are bounds-checked windowed reads; the
   frontend never executes file content.
3. **Operator error** — destructive actions require confirmation, and
   dangerous capability requires explicit opt-in *plus* confirmation *plus*
   audit trail (three-gate model below).
4. **Hostile requests via issues/PRs** — features that would turn GoHex into
   an attack, anti-forensic, or credential-theft tool are out of scope and
   will be declined (see [legal.md](legal.md)).

Not in scope: multi-user isolation, encrypting the examiner's disk, protection
against a compromised host, or a sandboxed process model (Stage 1 runs with
the user's own privileges).

## The three-gate model for dangerous operations

Any operation that can write to a physical device must pass **all** of:

1. **Capability gate** — `GOHEX_ALLOW_UNSAFE_WRITE=1` must be set in the
   environment; otherwise the service refuses before any dialog appears.
2. **Confirmation gate** — a two-step confirmation dialog (explicit
   acknowledgement text, not a plain OK).
3. **Audit gate** — the operation is appended to the audit log; a failure to
   write the audit entry aborts the operation.

Profiles add a fourth, independent gate: the `readonly` profile rejects all
edits inside the service layer, so a UI bug cannot mutate evidence.

## Safe-by-default configuration

`internal/config` ships defaults that are always the safe ones:

- Profile `analyst`, editing allowed only for document-level operations;
  physical writes never enabled.
- Update checks and telemetry **off** (no outbound network by default).
- Config and audit files are created with mode `0600` in the user config
  directory (`~/.config/gohex/` on Linux).

Security-relevant environment variables are limited to an explicit allowlist
(`GOHEX_ALLOW_UNSAFE_WRITE`, `GOHEX_UPDATE_CHECK`, `GOHEX_THEME`,
`GOHEX_LANG`, `GOHEX_PROFILE`).

## Audit log

- Location: `~/.config/gohex/audit.jsonl` (configurable).
- Format: append-only JSON lines — timestamp, operation, parameters, result.
- File mode `0600`; opened with `O_APPEND` so history cannot be silently
  rewritten through the app.
- Purpose: chain-of-custody evidence for casework (who changed what, when).

## Frontend/backend boundary

- The webview is **untrusted** in the sense that all authority lives in Go:
  every mutation goes through `internal/service`, which re-checks profile,
  permissions, bounds, and audit requirements. The UI can only *request*.
- Bindings are generated from the Go API; generated types are treated as
  possibly-null and validated at call sites.
- No `eval`, no remote content, no third-party scripts: the frontend bundle is
  embedded (`go:embed`) and served locally.
- CSP-friendly by construction: assets are same-origin only.

## Data handling

- Evidence files are opened read-only unless an edit is explicitly committed.
- Nothing is uploaded; there is no telemetry.
- Sandbox mode lets users rehearse edits and saves without any disk write.
- Hashes (sha256/sha1/md5/crc32/c/blake3/xxhash64) are provided for
  import/export verification.

## Reporting

Report vulnerabilities per [SECURITY.md](../SECURITY.md). Please include:
affected version (`gohex` banner / `pkg/version`), reproduction steps, and
whether the issue can cause data loss — data-loss bugs are treated as
security bugs.

## Supply chain

Release artifacts are defended in layers:

- **CI gates** (`.github/workflows/ci.yml`): `go vet`, `gofmt`, a ≥80%
  coverage floor, frontend type-check, and a bindings-regeneration diff
  check that fails when Go APIs and TypeScript bindings drift apart.
- **Lint & security** (`.github/workflows/security.yml`): golangci-lint
  (gofumpt, gosec, errcheck, …), `govulncheck`, and `gitleaks` over the
  full history.
- **SBOM**: every main-branch build emits CycloneDX and SPDX SBOMs via
  syft; release jobs attach the same documents to the GitHub release.
- **Signing**: release tags are signed with cosign (keyless, Sigstore
  public good instance) so `cosign verify` can prove a binary came from
  this repository's workflow. Verify with:

  ```sh
  cosign verify-blob --bundle gohex.sig.bundle gohex_linux_amd64.tar.gz
  ```

- **Checksums**: `SHA256SUMS` is published next to every release; the
  in-app updater (`UpdateDownload`) refuses any asset whose SHA-256 does
  not match the digest the examiner pasted — it never executes what it
  downloads.
- **Changelog**: `CHANGELOG.md` is generated from Conventional Commits by
  git-cliff (`cliff.toml`); releases cut from tags must not contain
  undocumented behavior changes.

Packaging manifests live next to the code they describe:
`packaging/flatpak/` (Flatpak), `packaging/snap/` (Snap),
`packaging/msi/` (WiX v4), `packaging/dmg/` (macOS DMG via create-dmg in
the release workflow).
