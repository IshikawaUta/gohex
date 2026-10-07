# GoHex architecture

GoHex is a desktop hex editor and digital-forensic suite written in Go with a
Wails v3 GUI (Svelte 5 frontend). This document describes the Stage 1 and
Stage 2 code that exists today, the boundaries that keep it safe, and how
later stages plug in.

## Layer overview

```
┌────────────────────────────────────────────────────────────┐
│ frontend/            Svelte 5 + TypeScript (Wails webview) │
│   virtual hex grid · tabs · find panel · dialogs · i18n    │
├──────────────────── generated bindings ────────────────────┤
│ internal/service     RPC façade (44 methods, events)        │
│   documents, search, hashing, images, partitions, fs, ...  │
├────────────────────────────────────────────────────────────┤
│ internal/hex         Document: journal, undo/redo, search  │
│ internal/core        Sources: files, mmap, windowed reads  │
│ internal/disk        MBR / EBR / GPT partition tables      │
│ internal/image       image containers (raw, E01, VHD, ...) │
│ internal/fs          read-only FAT/NTFS/ext/exFAT/ISO view │
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
- HFS+/APFS and multi-segment/Ex01/L01 variants are deliberately out of scope
  for Stage 2 and report *"not yet supported (roadmap stage 3)"* rather than
  pretending to parse them.

`internal/disk` parses MBR (including extended/EBR chains) and GPT into a
`Table` with non-fatal warnings instead of hard failures, and `internal/fs`
exposes a read-only `FS` (`List`/`Stat`/`ReadAt`) over FAT12/16/32, exFAT,
NTFS, ext2/3/4 and ISO9660 — case-insensitive where the real filesystem is,
case-sensitive where it is not.

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
| 2 ◐ | Disk & image reader (RAW/E01/VHD/VMDK/QCOW2/VHDX), partition tables, read-only file-system viewers (FAT/NTFS/ext/exFAT/ISO) + service APIs; GUI disk panel still to come. HFS+/APFS moved to stage 3 | `disk`, `image`, `fs`, `service` |
| 3 | Recovery & carving, case management & reports, browser artifacts | `recovery`, `forensics`, `browser`, `dump` |
| 4 | Memory viewer (read-only), crash-dump analyzer | `memory` |
| 5 | Scripting, utilities, packaging, signing, configurable keymap engine | `script`, `template`, `update` |

Placeholder directories exist for stages 3–5; they contain no code yet. HFS+
and APFS are intentionally deferred to stage 3: admitting a half-working
parser would be worse than saying "not yet supported".
Non-goal forever: anti-forensic features, credential extraction, stealth —
see [legal.md](legal.md).

## Build pipeline

`wails3 build` orchestrates: `go mod tidy` → `wails3 generate bindings` →
`npm install && npm run build` → `go build -tags production -trimpath -o bin/gohex`.
Bindings are generated from the service API; the frontend must treat every
generated field as possibly-null (they mirror Go slices/pointers) and import
types with `import type` where a value is not needed.
