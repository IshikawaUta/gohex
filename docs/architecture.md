# GoHex architecture

GoHex is a desktop hex editor and digital-forensic suite written in Go with a
Wails v3 GUI (Svelte 5 frontend). This document describes the Stage 1 through
Stage 3 code that exists today, the boundaries that keep it safe, and how
later stages plug in.

## Layer overview

```
┌────────────────────────────────────────────────────────────┐
│ frontend/            Svelte 5 + TypeScript (Wails webview) │
│   virtual hex grid · tabs · find panel · dialogs · i18n    │
├──────────────────── generated bindings ────────────────────┤
│ internal/service     RPC façade (69 methods, events)        │
│   documents, search, hashing, images, partitions, fs, ...  │
├────────────────────────────────────────────────────────────┤
│ internal/hex         Document: journal, undo/redo, search  │
│ internal/core        Sources: files, mmap, windowed reads  │
│ internal/disk        MBR / EBR / GPT partition tables      │
│ internal/image       image containers (raw, E01, VHD, ...) │
│ internal/memory      memory dumps (LiME, AVML, ELF core, MDMP, windump) │
│ internal/fs          read-only FAT/NTFS/ext/ISO/HFS+/APFS  │
│ internal/recovery    signature-based file carving          │
│ internal/browser     Chrome/Firefox/Safari artefact reader │
│ internal/forensics   case, evidence, timeline, reports     │
│ internal/script      sandboxed Starlark engine (read-only) │
│ internal/template    structure-template overlay (WinHex-style) │
│ internal/update      opt-in update check (GitHub releases) │
│ internal/keymap      configurable keymap engine             │
│ internal/sqlite      read-only SQLite + WAL merge (no cgo) │
│ internal/encoding    text codecs, Intel-HEX, S-records     │
│ internal/hash        sha*, md5, crc32/c, blake3, xxhash64  │
│ internal/audit       append-only audit log (0600)          │
│ internal/config      profiles, safe defaults, GOHEX_* env  │
├────────────────────────────────────────────────────────────┤
│ pkg/version          build-time version stamp              │
│ main.go              Wails app entry, asset embed          │
│ cmd/gohex-cli        read-only companion CLI (hash/info/search) │
└────────────────────────────────────────────────────────────┘
```

Dependency rule: arrows point down only. `frontend` talks to Go exclusively
through `internal/service`; lower packages never import `service` or Wails.

## Key design decisions

### Read-only by default

`internal/config` defines four profiles: `readonly` (hard policy — editing is
rejected by the service regardless of UI state), `analyst` (default: edit
documents, save to new files), `recovery`, `examiner` (audit-heavy casework).
Physical-disk writes are gated three ways: an explicit opt-in flag, a two-step
confirmation dialog, and an audit-log entry. Sandbox mode simulates saves
without touching the disk.

### Documents and the undo journal

`internal/hex.Document` wraps a `core.Source` and keeps an in-memory journal:

- Every mutation records `beforeID`/`afterID` state identifiers.
- `Dirty()` compares the current state ID with the saved state ID, so undoing
  back to the last save point reports *clean* (a bug fixed in Stage 1).
- The journal is bounded; `canUndo`/`canRedo` and labels are exposed through
  `DocInfo` for the toolbar.
- Edits go through `WriteBytes`/`InsertBytes`/`DeleteRange`/`FillRange` on the
  service; each is rejected when the active profile disallows editing.

### Windowed reads and the virtual grid

Files are opened once (`core.OpenFile`, memory-mapping with a configurable
limit) and read in chunks (`ReadWindow`, 64 KiB-class windows). The frontend
renders only visible rows (virtualized grid + overscan) and caches chunks per
epoch; changing documents or versions invalidates the epoch. This is what lets
Stage 1 open multi-gigabyte files with a small, flat memory footprint.

### Image containers, partitions and filesystems

`internal/image` turns a container file into the same read-only random-access
range that a plain file provides, so every engine above it is format-agnostic:

- **Detection is magic-based, never extension-based.** A `.img` that is really
  an E01 opens as E01.
- **Native readers** for raw and for EWF/E01 and L01 sets — single- or
  multi-segment (segments are discovered by naming convention next to the
  opened file; opening any segment reads the whole set), both byte orders
  auto-detected, chunks zlib-compressed or stored — and for Microsoft
  VHD (fixed and dynamic; the dynamic sector bitmap ahead of every block is
  honoured).
- **Delegated formats** (QCOW2, VMDK, VHDX) are flattened to a temporary raw
  file with `qemu-img convert`, which is removed on `Close`. These formats
  require `qemu-img` on `PATH`; `Open` says so explicitly when it is missing.
- Ex01 (EWF2) and SMART `.s01` variants are deliberately out of scope and
  report *"not yet supported (roadmap stage 3)"* rather than pretending to
  parse them; HFS+/APFS readers were added later in stage 3 (see below).

`internal/disk` parses MBR (including extended/EBR chains) and GPT into a
`Table` with non-fatal warnings instead of hard failures, and `internal/fs`
exposes a read-only `FS` (`List`/`Stat`/`ReadAt`) over FAT12/16/32, exFAT,
NTFS, ext2/3/4, ISO9660, HFS+/HFSX and APFS — case-insensitive where the
real filesystem is, case-sensitive where it is not. The Apple readers follow
the same eager-index philosophy as the SQLite reader: at `Probe` time the
HFS+ catalogue and extents-overflow B-trees, or the APFS checkpoint,
object maps and fs-tree, are walked once into in-memory maps, so every later
`List`/`Stat`/`ReadAt` is pure memory arithmetic. Both parsers report
honest attributes (`compressed` for decmpfs/HFS files, `encrypted` for
sealed volumes, `hardlink`/`symlink`/`readonly`) instead of guessing at
bytes they cannot decode, and every error is prefixed `fs/hfs+:` or
`fs/apfs:`.

The service layers them into `ProbeImage`/`OpenImage`/`OpenRange`,
`Partitions` and `ProbeFileSystem`/`FsList`/`FsStat`/`FsRead`/`FsExport`.
Filesystem sessions are cached for the lifetime of the app (so directory
listings do not re-parse the superblock) and released by `App.Close`.
`FsExport` writes to a destination that must not already exist and records
the SHA-256 of the copy in the audit log.

### Memory captures & crash dumps

`internal/memory` opens RAM captures and crash dumps read-only and exposes
their address segment map. LiME v1 files (magic `EMiL`) are walked as a
chain of 32-byte range headers — `(header, end-start+1 payload bytes)`
repeated to the end of the file — so every segment keeps its physical range
and file offset; Linux ELF core dumps contribute their `PT_LOAD` program
headers as virtual ranges; Windows minidumps take theirs from the
`Memory64List` stream or, failing that, the classic `MemoryList` stream.
`Locate` maps an address onto the byte offset holding it, and headerless
raw dumps fall back to a single segment without an address map. Detection
is magic-based like `internal/image`, truncated dumps are clamped to the
bytes that exist, and nothing is ever written to the capture.

AVML v2 captures (magic `AVML`, LiME-shaped 32-byte headers) store each
block as an in-house Snappy framed stream — chunk headers carry three-byte
little-endian lengths and masked CRC-32C checksums — followed by an 8-byte
compressed-length trailer; all-zero blocks are elided by writers, so their
address gaps simply do not appear as segments. `OpenReader` exposes every
capture as an uncompressed virtual `ReaderAt`: uncompressed formats read
straight from the file, while AVML decompresses each block on demand and
caches the segment being read. Windows 64-bit crash dumps (`PAGEDU64`)
parse their `DumpType`: type 1 (complete) maps the physical runs' pages
that follow the two header pages; type 5 (summary) walks the summary
header's page bitmap, mapping set bits to consecutive data pages. Other
dump types, 32-bit `PAGEDUMP` and Windows 8+ compressed kernel dumps report
an explicit not-yet-supported error.

The service surfaces all of this as `MemoryInfo`/`MemoryLocate` plus
`MemoryOpen`, which registers a capture (or a byte range of its
uncompressed view) as a hex document — the route compressed AVML takes —
behind the one-time ethics notice `docs/legal.md` requires.

### Search

`internal/hex` implements three pattern kinds (raw hex, text with case
folding, Go regexp) over a `Stream` abstraction, with forward/backward/wrapped
find and a bounded find-all (max 500 matches sent to the UI per query).

### Recovery and carving

`internal/recovery` finds files that no longer have directory entries. A run is
single-pass and read-only: the source is walked in 4 MiB windows, every
registered header is matched with `bytes.Index`, and candidates are queued in
offset order until their extent is known.

- **Extent is proven, never guessed.** Footer formats (JPEG, PNG, GIF, PDF,
  ZIP) must find their terminator inside the allowed region; header-only
  formats (BMP, RIFF/WAV, RIFF/AVI, MP4/MOV) carry a length field the parser
  reads back — the ISO-BMFF walker skips a multi-gigabyte `mdat` by reading
  only box headers. A format with neither is not registered.
- **Weak headers are validated first.** `BM` and `GIF8` alone would fire
  constantly, so each hit is checked structurally before it is queued. Random
  data produces no results.
- **Nested headers are not double-reported.** Results come out in ascending
  offset order and advance the cursor past the object just emitted, so a
  signature inside an already-carved file is skipped; carve it again from the
  extracted copy if you need it.
- **Truncated candidates are opt-in.** `Options.AllowTruncated` also reports
  objects whose footer lies past the scanned range; it is off by default
  because those are frequently false positives.
- An ordered queue is capped at 8192 unresolved candidates, and the service
  caps a run at 10000 results (100000 maximum), so a disk dense in signatures
  cannot exhaust memory or freeze the UI.

The service exposes `CarveTypes`, `CarveScan` (with `progress` events) and
`CarveExport`; the export writes with `O_EXCL` and records a SHA-256 audit
entry like every other extraction.

### Browser artifacts

`internal/browser` reconstructs what a browser recorded — history, downloads,
bookmarks — without ever touching credentials, cookies or form data. It is
built in three layers:

- **`internal/sqlite`** is a zero-dependency read-only reader for SQLite
  files. It parses the header, walks b-trees page by page, decodes cell
  payloads including overflow chains, and honours WAL by merging committed
  frames over the main image in memory — the database on disk is never
  written to or checkpointed. Rollback journals are detected and reported as
  a warning instead of being applied. There is no SQL engine: a table is
  scanned in full and filtered in Go, which keeps the dependency surface at
  zero and the parser inspectable. That also matters for CI: the build must
  stay `CGO_ENABLED=0`-clean, which rules out `mattn/go-sqlite3`.
- **Readers** (`chrome.go`, `firefox.go`, `safari.go`) map each vendor's
  schema: Chromium's `urls`/`visits`/`downloads`/`downloads_url_chains` with
  its 1601 epoch and JSON `Bookmarks` file; Firefox's `places.sqlite` with
  its annotations-based downloads and `dateAdded` bookmark columns; Safari's
  `history_items`/`history_visits` join performed in Go because the driver
  cannot be relied on. Every timestamp is normalised to `time.Time` in UTC.
- **`Report`** is the single value the service consumes: three slices plus a
  `Warnings` list, so a partially damaged profile yields what could be read
  rather than nothing at all.

Missing tables become warnings through `absorb`, missing files become
`ErrNotFound`, and an unrecognised `Browser` value is an error rather than a
silent guess. The `Browser` and `BookmarkKind` types are string enums because
they cross the JSON boundary to the front end — an iota would force the UI to
mirror the constant order.

The service exposes `BrowserProfiles`, `BrowserRead` and `BrowserExport`;
both read and export are audited (`op=browser`, `mode=browser_<kind>`), the
export writes with `O_EXCL` and records a SHA-256, and the GUI gates the
dialog behind a one-time ethics notice required by `legal.md`.

### Case management and reports

`internal/forensics` is the casework layer: what was examined, when it was
added, what it hashed to, and what the examiner concluded.

- **A case is a plain JSON document** carrying `schemaVersion`. Saving is
  atomic — a temporary file in the same directory is written, flushed and
  renamed over the destination — and the file is mode `0600`, because a case
  names people and systems. A file that is not a case is `ErrNotCase`; a file
  from a newer schema is `ErrSchemaTooNew` rather than a half-read import.
- **Evidence is referenced, never copied.** An entry holds path, size and the
  SHA-256 streamed from the file when it was added. `VerifyEvidence`
  re-hashes it and reports match or mismatch; a file that has vanished is an
  error, not a mismatch, because nothing was checked at all.
- **Findings** carry a severity (`info`…`critical`) and may point at the
  evidence they rest on; an unknown identifier or severity is refused rather
  than stored. **Events** make the timeline, returned oldest-first with
  undated entries last — an unknown time is not an early one.
- **Reports are a rendering, not a second source of truth.**
  `BuildReport` flattens the case into a `ReportDocument` with the timeline
  already sorted, so the HTML and the JSON cannot disagree. `checksum` is the
  SHA-256 of the canonical (compact) JSON encoding of the case record,
  embedded in both forms so a reader can tie a report back to the case file
  they were given. The HTML template is embedded in the binary and is fully
  self-contained — no scripts, fonts or remote assets — so it still renders
  correctly when archived years later, and it is laid out for print.

The service exposes `CaseState`, `CaseNew`, `CaseOpen`, `CaseClose`,
`CaseSave`, `CaseSetMeta`, `CaseEvidenceAdd`, `CaseEvidenceVerify`,
`CaseFindingAdd`, `CaseEventAdd` and `CaseReport`. Exactly one case may be
open: a second `New` or `Open` is refused instead of silently discarding
unsaved findings, and evidence hashing runs outside the lock so a
multi-gigabyte image cannot freeze the rest of the application. Every
lifecycle step is audited — `case` for open/save/close, `import` with the
digest for evidence, `hash_verify` for both outcomes of a verification (a
mismatch is logged as an error so an auditor scanning for failed integrity
checks finds it), and `export` for the report, which is written with
`O_EXCL` and hashed.

Non-goals: no evidence copying, no cloud sync, no automatic conclusions —
the package records what the examiner tells it and refuses to record things
it cannot validate.

### Scripting

`internal/script` embeds Starlark (`go.starlark.net`) as the automation
engine. Scripts run against the open documents through a four-method `Host`
interface (`Docs`/`Read`/`Find`), so the engine itself knows nothing about
the service or the GUI, and the service injects a host bound to the current
document set.

- **Sandboxed by construction.** The `gohex` module (`docs`/`read`/`find`/
  `hash`/`version`) is the only capability a script receives; `load()` is
  disabled and the Starlark environment has no filesystem, network, clock or
  randomness.
- **Bounded, not trusted.** A wall-clock timeout (30 s) and an interpreter
  step limit (10^6) stop runaway loops — the timeout cancels the evaluation
  through `Thread.Cancel` rather than killing the process — and `print()`
  output is captured (1 MiB cap) instead of reaching any real stdout.
  Recursion and global reassignment stay disabled; top-level `for`/`if` and
  `while` are allowed because scripts are programs, not library files.
- **Failures are results.** A script that errors reports
  `ScriptResult.Error` (carrying the interpreter's backtrace) while keeping
  the output captured up to the failure; only infrastructure problems
  (missing or oversized source file) fail the `ScriptRun` call itself.
  Every run is audited as a `script` event with duration and outcome.

The service's `scriptHost` implements the engine's `Host` against the open
documents: reads are clamped to the document like `ReadWindow`, finds reuse
the same ASCII text-pattern scanner as the search bar, and results are
capped (500 hits per call, 4 KiB patterns). The GUI Script panel runs a
chosen `.star` file and shows the captured output; it never writes anything
— scripts read the live document, including unsaved edits.

### Structure templates

`internal/template` is the structure-overlay engine: a flat list of
offset-addressed typed fields (the WinHex template model), parsed from a
strict `key=value` file format and applied to any `io.ReaderAt` — in the
service, an open document.

- **Strict parsing.** An unknown key or type, a missing name, a duplicate
  Type/Name or a bad offset is an error at load time, never a silently
  skipped field: a wrong template is refused before it can mislabel data.
- **Typed display, not typed storage.** Fields decode into display strings —
  integers as hex + decimal, FILETIME and Unix times as UTC timestamps
  (values past year 9999 report "out of range" instead of wrapping), GUIDs
  in the Microsoft mixed-endian layout regardless of the template's byte
  order, strings NUL-trimmed and quoted.
- **All-or-nothing apply.** A template whose span runs past the end of the
  document is an error; a half-filled table would be worse than no table.

The service exposes `TemplateLoad` (parse + audit) and `TemplateApply`
(overlay at an offset, audited per apply). The GUI Template panel shows the
field table, an offset box with a "use cursor" shortcut, and the decoded
values.

### Update check

`internal/update` probes the GitHub "latest release" endpoint for a newer
GoHex version. It is strictly opt-in (`GOHEX_UPDATE_CHECK=1`; see
[legal.md](legal.md) — no outbound connections by default), and every
failure mode is soft data: an unreachable server, an HTTP error, a
malformed or oversized response lands in `Result.Error`, never as a Go
error or a panic. Version ordering is a small numeric-segment comparator
with prerelease precedence (`1.0.0 > 1.0.0-rc2 > 1.0.0-rc1`, build
metadata ignored). The service audits enabled probes; disabled checks are
local and unaudited. `GOHEX_UPDATE_URL` overrides the endpoint for mirrors
and offline test fixtures.

### Keymap engine

`internal/keymap` is the single source of truth for keyboard shortcuts:
it defines the action catalogue (`file.open` … `help.shortcuts`), parses
and canonicalises chord strings (`Ctrl+Shift+S`; aliases Control/Cmd/
Option/Super fold onto Ctrl/Meta/Alt; the canonical form fixes modifier
order, uppercases letters and F-keys, title-cases named keys), validates
whole keymaps (unknown action, unparseable chord, two actions on one
chord — first error wins) and resolves chords to action IDs.
`config.DefaultShortcuts` is derived from the catalogue so the two cannot
drift, and `config.Validate` runs `keymap.Validate` on every load and
save — a hand-edited `config.json` cannot smuggle in a broken keymap.
The frontend mirrors canonicalisation in `lib/keymap.ts`; the global
dispatcher in `App.svelte` resolves the captured event through the
user's map instead of hard-coded keys, and the Preferences dialog edits
chords (empty = unbound) with the stock map available via
`ShortcutDefaults`. Reserved actions keep their bindings until their UI
lands.

### Service events

The service emits `progress` events (`op`, `done`) for long operations
(hashing, future imaging/copy tasks) through a tiny `Emitter` interface that
`main.go` adapts to the Wails event bus — keeping `internal/service`
testable without a GUI (13+ table tests, ≥80% coverage on every package).

## Frontend structure

```
frontend/src/
  main.ts            mount + global error logging
  App.svelte         layout, global keymap, dialog routing
  lib/state.svelte   central $store (Svelte 5 runes)
  lib/api.ts         binding imports + error helpers
  lib/actions.ts     all service calls (open, save, goto, hash …)
  lib/hex/           virtual grid, cell rendering, selection, editing
  lib/FindPanel.svelte, Toolbar, TabBar, StatusBar
  lib/dialogs/       Preferences, About, native-dialog wrappers
```

State flows one way: UI event → `actions.ts` → service call → store update →
re-render. The store is the only shared mutable state.

## Testing strategy

- Go: `go test ./...` — unit + table tests per package, `go vet`, coverage
  gate ≥80% on project code (excluding Wails build scaffolding).
- Frontend: `npm run check` (svelte-check, zero errors/warnings required).
- GUI smoke: launch with `GOHEX_SKIP_DISCLAIMER=1 GOHEX_OPEN=<file>`, verify
  window, rendering, idle CPU (must be ~0), and exercise flows.

## Roadmap stages

| Stage | Scope | Packages added |
|---|---|---|
| 1 ✅ | Hex editor core + GUI shell | `core`, `hex`, `encoding`, `hash`, `audit`, `config`, `service` |
| 2 ✅ | Disk & image reader (RAW/E01/VHD/VMDK/QCOW2/VHDX), partition tables, read-only file-system viewers (FAT/NTFS/ext/exFAT/ISO) + service APIs + GUI disk panel. HFS+/APFS moved to stage 3 | `disk`, `image`, `fs`, `service` |
| 3 ◐ | Carving, browser artifacts, case management & reports, HFS+/APFS file systems and multi-segment E01/L01 image sets are done. `internal/dump` still holds only its planned layout | `recovery`, `browser`, `forensics`, `dump` |
| 4 ✅ | Memory viewer & crash-dump analyzer: LiME, AVML (Snappy), raw, ELF core, Windows minidump and Windows 64-bit dumps (complete + bitmap) | `memory` |
| 5 ◐ | Scripting engine, structure templates, opt-in update check and the configurable keymap engine shipped (all with GUI surfaces). Utilities, packaging and signing remain | `script`, `template`, `update`, `keymap` |

Stage 3 ships `internal/recovery`, `internal/browser` and `internal/forensics`.
`internal/dump` still holds only its planned sub-directory layout, which is
for **resources rather than Go packages** — the same convention
`internal/forensics` keeps for its report template under `forensics/report`.
The Go code stays at the package root because `case` is not a legal Go package
name. HFS+ and APFS arrived in the last stage-3 slice as eager, read-only
parsers: admitting a half-working parser would be worse than saying "not yet
supported", so both ship only with their full feature sets (HFS+ with the
catalogue, extents-overflow and key-compare folding; APFS with checkpoint
adoption, object maps, hashed directory keys and fext trees). Multi-segment
E01/L01 sets joined the image layer the same way: each segment is
self-contained (header, sections, terminator), sets are discovered by naming
convention (E01..E99, EAA..ZZZ, L01..L99, ...) and a wrong claim, a missing
segment or a mixed E01/L01 set is rejected up front instead of silently
reading short.
Stage 5 opened with the scripting engine: `internal/script` embeds Starlark
with the read-only `gohex` capability module, the service exposes it as
`ScriptRun`, and the GUI gained a Script panel. Structure templates
(`internal/template`) followed the same shape: a strict parser, an
all-or-nothing apply and a GUI Template panel. The opt-in update check
(`internal/update`) brought soft failures and audited probes with no
outbound connection unless `GOHEX_UPDATE_CHECK=1`, and the keymap engine
(`internal/keymap`) made the shortcut map a validated, editable
configuration instead of hard-coded key handlers. The remaining stage-5
scope — utilities, packaging and signing — is release engineering on top
of the shipped engines.
Non-goal forever: anti-forensic features, credential extraction, stealth —
see [legal.md](legal.md).

## Build pipeline

`wails3 build` orchestrates: `go mod tidy` → `wails3 generate bindings` →
`npm install && npm run build` → `go build -tags production -trimpath -o bin/gohex`.
Bindings are generated from the service API; the frontend must treat every
generated field as possibly-null (they mirror Go slices/pointers) and import
types with `import type` where a value is not needed.
