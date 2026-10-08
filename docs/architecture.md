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
│ internal/service     RPC façade (61 methods, events)        │
│   documents, search, hashing, images, partitions, fs, ...  │
├────────────────────────────────────────────────────────────┤
│ internal/hex         Document: journal, undo/redo, search  │
│ internal/core        Sources: files, mmap, windowed reads  │
│ internal/disk        MBR / EBR / GPT partition tables      │
│ internal/image       image containers (raw, E01, VHD, ...) │
│ internal/fs          read-only FAT/NTFS/ext/ISO/HFS+/APFS  │
│ internal/recovery    signature-based file carving          │
│ internal/browser     Chrome/Firefox/Safari artefact reader │
│ internal/forensics   case, evidence, timeline, reports     │
│ internal/sqlite      read-only SQLite + WAL merge (no cgo) │
│ internal/encoding    text codecs, Intel-HEX, S-records     │
│ internal/hash        sha*, md5, crc32/c, blake3, xxhash64  │
│ internal/audit       append-only audit log (0600)          │
│ internal/config      profiles, safe defaults, GOHEX_* env  │
├────────────────────────────────────────────────────────────┤
│ pkg/version          build-time version stamp              │
│ main.go              Wails app entry, asset embed          │
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
- **Native readers** for raw and single-segment EWF/E01 (both byte orders are
  auto-detected; chunks may be zlib-compressed or stored) and for Microsoft
  VHD (fixed and dynamic; the dynamic sector bitmap ahead of every block is
  honoured).
- **Delegated formats** (QCOW2, VMDK, VHDX) are flattened to a temporary raw
  file with `qemu-img convert`, which is removed on `Close`. These formats
  require `qemu-img` on `PATH`; `Open` says so explicitly when it is missing.
- Multi-segment/Ex01/L01 variants are deliberately out of scope and report
  *"not yet supported (roadmap stage 3)"* rather than pretending to parse
  them; HFS+/APFS readers were added later in stage 3 (see below).

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
| 3 ◐ | Carving, browser artifacts, case management & reports and HFS+/APFS file systems are done. Multi-segment E01/L01 still to come | `recovery`, `browser`, `forensics`, `dump` |
| 4 | Memory viewer (read-only), crash-dump analyzer | `memory` |
| 5 | Scripting, utilities, packaging, signing, configurable keymap engine | `script`, `template`, `update` |

Stage 3 ships `internal/recovery`, `internal/browser` and `internal/forensics`.
`internal/dump` still holds only its planned sub-directory layout, which is
for **resources rather than Go packages** — the same convention
`internal/forensics` keeps for its report template under `forensics/report`.
The Go code stays at the package root because `case` is not a legal Go package
name. HFS+ and APFS arrived in the last stage-3 slice as eager, read-only
parsers: admitting a half-working parser would be worse than saying "not yet
supported", so both ship only with their full feature sets (HFS+ with the
catalogue, extents-overflow and key-compare folding; APFS with checkpoint
adoption, object maps, hashed directory keys and fext trees).
Non-goal forever: anti-forensic features, credential extraction, stealth —
see [legal.md](legal.md).

## Build pipeline

`wails3 build` orchestrates: `go mod tidy` → `wails3 generate bindings` →
`npm install && npm run build` → `go build -tags production -trimpath -o bin/gohex`.
Bindings are generated from the service API; the frontend must treat every
generated field as possibly-null (they mirror Go slices/pointers) and import
types with `import type` where a value is not needed.
