# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added

- **Fuzzing & benchmarks**: 12 fuzz targets across parser packages
  (encoding, filesystems, hash, recovery, forensics, raid, restapi, …) and
  I/O benchmarks for clone/hash/read paths.
- **Carving signatures expanded 9 → 35 types** (images, office, OLE, audio,
  video, archives, executables) with low-confidence fallbacks and
  truncated-extent flags.
- **Memory dump analyzer v2**: minidump modules/threads/exception stream +
  context registers, ELF core notes (NT_FILE, NT_PRSTATUS), Windows
  DUMP_HEADER64 BugCheck codes, hibernation/pagefile/vmem detection.
- **Reports in JSON + HTML + PDF + DOCX** (dependency-free PDF 1.4 writer
  and OOXML ZIP writer) with SHA-256 case checksum embedded in every format.
- **Bates numbering** for evidence and timeline exhibits in JSON/PDF/DOCX
  reports (prefix/start/zero-pad width, applied to report copies only —
  the case file stays unnumbered); refused for HTML.
- **Timeline forensik**: kind/date/search filter UI, CSV/JSON export.
- **Utilities suite**: entropy heatmap, byte frequency, hex calculator,
  regex tester, strings, split/join, secure delete (single-pass zero +
  multi-pass DoD 5220.22-M), password/UUID/ULID generator, timestamp
  converter, RNG capture, selection export to PNG.
- **Disk clone v2**: gzip/zstd compression, split volumes, resume via
  checkpoint file, bad-sector log, progress events, `gohex-cli clone`.
- **RAID 0/1/5/6 interpreter** (read-only): GF(2^8) Reed-Solomon for RAID6,
  degraded reads with missing members, GUI dialog, cross-stripe verified.
- **NTFS alternate data streams**: list resident/named streams per file
  (record-level, works without ntfs-3g), open as hex, export hashed copy;
  compressed/encrypted streams are listed but refused.
- **FUSE read-only mount** (linux, go-fuse v2): kernel `ro` option +
  node modes 0444/0555 + EROFS on open-for-write; mountpoint must be empty;
  unmount on shutdown; graceful error on non-Linux builds.
- **Bookmarks & offset history**: per-file bookmarks persisted to localStorage
  (Ctrl+D / Ctrl+Shift+B), back/forward offset navigation (Alt+←/→),
  drag-and-drop file open.
- **Compare dialog**: pairwise A×B/C/D four-way compare with sync reveal
  (⇔), per-diff jump buttons.
- **Macro record/replay**: goto/find/copy/bookmark/selectAll/wait steps,
  stops at first failing step, export/import JSON (`gohex-macro-v1`).
- **Help dialog** (F1): filterable shortcut table, getting-started tour,
  synthetic sample-evidence generator (64 KiB MZ/PE + PNG + JPEG + ZIP +
  marker + entropy regions + UTF-16LE strings).
- **gohex-server** REST API: loopback-only bind (refuses non-loopback),
  bearer-token auth (constant-time compare, token required), opt-in;
  endpoints for version, documents (open/data/find) and fs (probe,
  partitions, list, export). Ships as `cmd/gohex-server`.
- **Carved-file gallery preview**: selecting a carved JPEG/PNG/GIF/BMP/WebP
  shows a data-URL thumbnail (1 MiB cap, read-only, audited).
- **Verified update download**: paste asset URL + published SHA-256; the
  download is streamed through the hash with a 256 MiB cap, kept only on
  match, never executed; gated behind `GOHEX_UPDATE_CHECK=1`; audited.
- **Supply-chain CI**: golangci-lint (gofumpt/gosec/errcheck/…) config,
  security workflow (golangci-lint, govulncheck, gitleaks, SBOM via syft),
  cosign keyless signing in the release workflow, git-cliff changelog
  config, Flatpak/Snap/MSI/DMG packaging manifests under `packaging/`.

- **Hex editor core** (`internal/hex`): span-overlay document model that opens
  files larger than 4 GB without loading them into memory; overwrite, insert,
  delete, fill; unlimited undo/redo (memory bounded by edited bytes).
- **Search engine**: hex, text (multiple encodings), wildcard (`??`), and
  regex (RE2) patterns with Find Next / Previous / All, forward & backward.
- **Encodings** (`internal/encoding`): binary ↔ hex ↔ ASCII, UTF-8/UTF-16
  column rendering, EBCDIC table, Intel HEX and Motorola S-record import/export.
- **Hashing** (`internal/hash`): CRC-16/32, Adler-32, MD5, SHA-1, SHA-256,
  SHA-512, BLAKE2b, BLAKE3, xxHash over files or selections.
- **Audit log** (`internal/audit`): JSON Lines records for every open/save/write
  action, with optional AES-256-GCM encryption.
- **Configuration** (`internal/config`): themes (light/dark/high-contrast),
  font settings, keyboard shortcuts, user profiles (Analyst/Recovery/
  Read-Only/Examiner), EN + ID localisation scaffolding.
- **GUI shell** (Wails v3 + Svelte 5): virtual-scrolling 3-column hex grid
  (offset | hex | text) for huge files, tabs, status bar, goto-offset,
  search/replace dialogs, undo/redo, save/save-as, drag & drop, context menus,
  keyboard shortcuts, theming.
- **Tools dropdown**: the nine forensic panels (Disk, Carve, Browser,
  Memory, Case, Script, Template, Crash report, Compare) collapsed into a
  single keyboard-navigable Tools menu in the toolbar — arrow keys to move,
  Escape or an outside click to dismiss, panel descriptions as tooltips.
- **CLI companion** (`cmd/gohex-cli`): hash, search, info — read-only defaults.
- **Disk images & partitions** (`internal/image`, `internal/disk`): magic-based
  detection of RAW, EWF/E01 and L01 sets (single- or multi-segment; segments
  are discovered by naming convention and the whole set is read when any
  segment is opened), native VHD and — through `qemu-img` — QCOW2/VMDK/VHDX;
  MBR, extended/EBR and GPT parsing with non-fatal warnings instead of hard
  failures.
- **Read-only file systems** (`internal/fs`): FAT12/16/32, exFAT, NTFS,
  ext2/3/4 and ISO9660 listing, stat and byte reads, surfaced through a GUI
  disk panel that walks an image's partitions and exports files with a
  SHA-256 audit record.
- **File carving** (`internal/recovery`): single-pass header/footer scanner for
  JPEG, PNG, GIF, PDF, ZIP and length-framed BMP, WAV, AVI, MP4. Every result
  carries a proven offset and size, signatures nested inside an already-carved
  object are not double-reported, and random data yields nothing. Exposed as
  `CarveTypes`/`CarveScan`/`CarveExport` with progress events and a GUI carve
  panel.
- **Browser artifacts** (`internal/browser`, `internal/sqlite`): a
  zero-dependency read-only SQLite reader — b-tree walk, overflow payloads and
  WAL frame merging without writing to the file — behind Chrome/Chromium,
  Firefox and Safari readers for history, downloads and bookmarks. Exposed as
  `BrowserProfiles`/`BrowserRead`/`BrowserExport` with CSV and JSON export,
  SHA-256 audit records, a GUI browser panel, and a one-time ethics notice as
  required by `docs/legal.md`. No credential, cookie or form-data extraction.
- **Case management & reports** (`internal/forensics`): a JSON case file with
  a schema version that records evidence (path, size, SHA-256 — never a copy
  of the bytes), findings with severity, and a sorted timeline; evidence can
  be re-verified and a mismatch is recorded as a failed integrity check.
  Reports render to a self-contained HTML document or JSON, both carrying a
  checksum over the canonical case record, with an embedded template that
  needs no network. Exposed as `CaseState`/`CaseNew`/`CaseOpen`/`CaseSave`/
  `CaseEvidenceAdd`/`CaseEvidenceVerify`/`CaseFindingAdd`/`CaseEventAdd`/
  `CaseReport` and a GUI case panel.
- **HFS+/APFS file systems** (`internal/fs`): read-only mounts for
  HFS+/HFSX — volume header, catalogue and extents-overflow B-trees with
  extent-overflow records, key-compare case folding, UTF-16 names, decmpfs
  compression and hardlink/symlink/readonly flags — and for APFS: latest
  valid checkpoint adoption, object-map resolution (physical and virtual),
  fs-tree and dedicated fext-tree walks, hashed directory keys per the
  incompat flags, xfield dstreams and the container's single volume, all
   behind the existing `ProbeFileSystem`/`FsList`/`FsStat`/`FsRead`/
   `FsExport` APIs. Images are assembled by in-test builders, so no
   `mkfs.hfsplus`/`mkfs.apfs` is needed to run the suite.
- **Memory captures** (`internal/memory`): magic-based detection of LiME v1
  captures with their physical segment map — every `(header, payload)` block
  keeps its physical range and file offset, and a physical address is located
  back to the exact byte — plus a headerless raw fallback, surfaced through
  `MemoryInfo`/`MemoryLocate`, a GUI memory panel that opens any segment as
  hex, and the one-time ethics notice as required by `docs/legal.md`.
  Strictly read-only.
- **Crash dumps** (`internal/memory`): read-only parsing of Linux ELF core
  dumps (`ET_CORE` `PT_LOAD` segments) and Windows minidumps (`Memory64List`
  / `MemoryList` streams) with virtual-address locate through the same
  `MemoryInfo`/`MemoryLocate` APIs and memory panel; truncated dumps are
  clamped to the bytes that exist.
- **AVML & Windows kernel dumps** (`internal/memory`): AVML v2 captures —
  LiME-shaped headers whose blocks are Snappy framed streams (three-byte
  chunk lengths, masked CRC-32C) with an 8-byte length trailer — and
  Windows 64-bit crash dumps (`PAGEDU64`): complete dumps via their
  physical run table, bitmap dumps via the summary header's page bitmap.
  A new `OpenReader`/`MemoryOpen` pair exposes any capture as an
  uncompressed virtual view (AVML blocks decompress on demand), the memory
  panel routes compressed captures through it, and remaining gaps — 32-bit
  `PAGEDUMP`, Windows kernel/small dumps, Windows 8+ compressed dumps —
   report explicit errors.
- **Automation scripts** (`internal/script`): a sandboxed Starlark engine
  (go.starlark.net) whose `gohex` module gives scripts read-only access to
  the open documents (`docs`/`read`/`find`/`hash`/`version`) — no
  filesystem, network, clock or randomness, module loading disabled —
  bounded by a 30-second timeout, a one-million-step interpreter limit and
  capped `print()` output. Failures are reported with the interpreter
  backtrace in the result (not as a Go error), and every run is audited as
  a `script` event. Exposed as `ScriptRun` with a GUI Script panel.
- **Structure templates** (`internal/template`): WinHex-style structure
  overlays — a strict key=value template format with typed fields (signed
  and unsigned integers, floats, byte buffers, strings, GUIDs in the
  Microsoft mixed-endian layout, FILETIME and Unix timestamps, booleans,
  arrays, little/big endian), applied to an open document at any offset with
  all-or-nothing span validation. Exposed as `TemplateLoad`/`TemplateApply`
  with per-apply audit records and a GUI Template panel that can reuse the
  cursor offset.
- **Update check** (`internal/update`): opt-in probe of the GitHub latest-
  release endpoint (`GOHEX_UPDATE_CHECK=1`, `GOHEX_UPDATE_URL` override) with
  numeric-segment + prerelease version ordering; every failure mode (offline,
  HTTP error, malformed or oversized response) is reported as data in the
  result, never as a Go error. Exposed as `UpdateCheck` with an audited
  probe and a **Check for updates** button in the About panel.
- **Configurable keymap engine** (`internal/keymap`): an action catalogue
  (`file.open` … `help.shortcuts`) with chord parsing and canonicalisation
  (Ctrl/Alt/Shift/Meta with Control/Cmd/Option/Super aliases), whole-map
  validation (unknown actions, bad chords and duplicate bindings are
  rejected with the reason) and chord-to-action resolution. The stock
  WinHex-flavoured defaults are derived from the catalogue,
  `config.Validate` runs on every load and save, the GUI dispatches global
  keys through the user's map instead of hard-coded handlers, and the
  Preferences dialog edits every chord (empty unbinds, reset restores the
  defaults via `ShortcutDefaults`).
- **Crash-report parsers** (`internal/dump`): content-based parsing of
  macOS/iOS `.ips` (header + body JSON), Android tombstones (banner /
  build fingerprint / signal / backtrace line scan) and Windows WER
  `Report.wer` (EventType, app version, FILETIME, signature records) into
  one structured `Report`. Frames are reported verbatim — no
  symbolication; malformed or unrecognized input errors instead of
  guessing. Exposed as `DumpInfo` with audit records and a GUI Crash
  report panel.
- **Binary compare** (`internal/compare`): range diff of two open
  documents — 64 KiB equal-block fast path, byte-level scan inside
  differing blocks only, contiguous differing ranges capped at 500 with
  exact equal/differing counts and the first differing offset. Size
  mismatches contribute one trailing range. Exposed as
  `CompareDocuments` with a GUI Compare panel.
- **Release packaging & signing** (`.github/workflows/release.yml`):
  tag-driven pipeline that cross-compiles `gohex-cli` for linux/windows/
  darwin × amd64/arm64, builds and packages the Linux GUI (deb, rpm,
  AppImage — verified locally) with best-effort NSIS and macOS `.app`
  jobs, enforces `pkg/version` + `build/config.yml` against the tag,
  writes `SHA256SUMS.txt` and attaches a detached armored GPG signature
  when the `GPG_PRIVATE_KEY`/`GPG_PASSPHRASE` repository secrets are
  configured, then creates the GitHub release. Fixed an invalid
  `runner`-context expression in the CI Windows build shell that
  actionlint flagged (the step was silently failing behind
  `continue-on-error`).
- Documentation: architecture, user guide, security, legal, release.
- CI: GitHub Actions build/test/lint matrix for Linux, Windows, macOS.

### Fixed

- **Raid tests**: cross-stripe logical order expectation corrected
  (`col0‖col1` per stripe); Raid5/Raid6 pad data to whole stripes — a
  `Size: 1` placeholder had collapsed the array size to 0, so the tests
  were passing for the wrong reason.
- **Minidump**: Memory64List type corrected 7 → 9; DumpHeader64 signature
  check tightened.
- **Preferences dialog**: pressing ⚙ (or Ctrl+,) opened nothing —
  `structuredClone()` on the reactive `$state` proxy of the loaded
  preferences threw `DataCloneError` on WebKitGTK, which aborted the
  dialog's mount effect before anything rendered. Clone a
  `$state.snapshot()` of the preferences instead (verified end-to-end
  against the local build).
- **Light theme**: the `Ctrl+O` hint chip on the welcome screen
  rendered white-on-light — it inherited the primary button's white
  text onto its raised background; give `kbd` an explicit
  `color: var(--text)`.

[Unreleased]: https://github.com/IshikawaUta/gohex/compare/HEAD...HEAD
