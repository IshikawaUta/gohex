# GoHex

**Hex editor & digital forensic suite** — a cross-platform (Windows / Linux / macOS, amd64 & arm64) desktop application written in Go with a native GUI (Wails v3 + Svelte). GoHex is designed as a lawful, transparent, production-grade alternative in the spirit of classic hex editors and forensic imaging tools.

> **DISCLAIMER — READ BEFORE USE**
>
> GoHex is provided for use **only on systems and data you own or for which you hold documented written authorization**. Unauthorized access to computer systems and data may be a crime in your jurisdiction.
>
> - All operations are **read-only by default**. Writing to physical disks or partitions requires an explicit flag, a two-step confirmation dialog, and is recorded in an audit log.
> - This tool contains **no** anti-forensic features, full-disk wiping, password/encryption bypass, live RAM editing, credential extraction, stealth, log deletion, or malware capabilities. Such requests will be declined.
> - **No telemetry by default.** No outbound network connections by default (the update checker is opt-in and off by default).
> - The browser-artifact, memory, and crash-dump modules display an ethics notice the first time they are opened.
>
> See [docs/legal.md](docs/legal.md) and [SECURITY.md](SECURITY.md). Licensed under the [Apache License 2.0](LICENSE).

## Status

Stages 1–4 are done (hex editor core + GUI shell, disk images & partitions,
recovery/browser/case tooling, memory forensics). Stage 5 has shipped its
engines (scripting, templates, update check, keymap); utilities, packaging
and signing remain. The full roadmap lives in [docs/architecture.md](docs/architecture.md).

| Area | Status |
|---|---|
| Hex editor (open >4 GB, edit, undo/redo, search, save) | ✅ |
| GUI shell (virtual grid, tabs, themes, shortcuts) | ✅ |
| Disk & image reader (RAW/E01/L01/VHD/QCOW2/VMDK/VHDX, multi-segment) + partition tables | ✅ stage 2 |
| Read-only file system browsers (FAT/NTFS/ext/exFAT/ISO) | ✅ stage 2 |
| HFS+/APFS file system support (read-only) | ✅ stage 3 |
| Data recovery & carving | ✅ stage 3 |
| Forensic case management & reports | ✅ stage 3 |
| Browser artifact parser | ✅ stage 3 |
| Memory viewer & crash-dump analyzer (LiME/AVML/raw/ELF core/minidump/Windows dumps) | ✅ stage 4 |
| Crash-report parsers (.ips / tombstone / WER) | ✅ stage 3 |
| Binary compare (differing byte ranges of two open documents) | ✅ stage 5 |
| Scripting engine + structure templates (sandboxed Starlark, WinHex-style overlays, GUI panels) | ✅ stage 5 |
| Update check (opt-in GitHub releases probe) | ✅ stage 5 |
| Configurable keymap engine (validated shortcuts, Preferences editor) | ✅ stage 5 |
| Companion CLI `gohex-cli` (read-only hash, info, search) | ✅ stage 5 |
| Utilities, packaging, signing | 🔜 stage 5 |

## Build & run

Prerequisites: Go ≥ 1.25, Node.js ≥ 20 (GUI), platform WebView development libraries.

- **Linux**: `libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config`
- **Windows**: WebView2 Runtime (preinstalled on Win 10/11) + MinGW-w64 for CGO builds
- **macOS**: Xcode Command Line Tools

```bash
# Tests (all platforms, headless) + frontend type check
go test ./...
npm --prefix frontend run check

# GUI (development)
npm --prefix frontend run build && go run .

# Production build via the Wails pipeline → bin/gohex
wails3 build

# Smoke-run (disclaimer pre-accepted, file opened at start)
GOHEX_SKIP_DISCLAIMER=1 GOHEX_OPEN=testdata/sample.bin ./bin/gohex
```

Cross-compiling the GUI requires the target OS toolchain (CGO); release binaries are produced by GitHub Actions — see [docs/release.md](docs/release.md).

## Usage examples

```bash
# Open a 6 GB disk image (read-only profile recommended)
./bin/gohex evidence.dd

# Inspect and hash inside the GUI
#   toolbar → "Hash…" → SHA-256 shown in the status bar

# Search a signature (Ctrl+F → mode "hex")
#   4D 5A 90 00  → matches jump with Enter / Shift+Enter

# Editing only happens when the profile allows it; physical-disk writes
# (stage 2+) additionally require GOHEX_ALLOW_UNSAFE_WRITE=1, a two-step
# confirmation, and an audit-log entry.
```

The companion CLI (`cmd/gohex-cli`) provides read-only `hash`, `info` and
`search`; the GUI is the only place with write paths.

## Responsible use

- Use only on data you are authorized to examine.
- Preserve chain of custody: enable the audit log for casework and verify hashes on import/export.
- Report vulnerabilities per [SECURITY.md](SECURITY.md). Do not open issues requesting bypass, anti-forensic, or credential-extraction features — they will be declined.

## Documentation

- [Architecture](docs/architecture.md) · [User guide](docs/user-guide.md) · [Security](docs/security.md)
- [Legal & ethics](docs/legal.md) · [Release process](docs/release.md)

## Contributing

Sign-off (DCO) required — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
