# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added

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
  Strictly read-only; AVML and crash dumps are still to come with the
  crash-dump analyzer.
- Documentation: architecture, user guide, security, legal, release.
- CI: GitHub Actions build/test/lint matrix for Linux, Windows, macOS.

[Unreleased]: https://github.com/IshikawaUta/gohex/compare/HEAD...HEAD
