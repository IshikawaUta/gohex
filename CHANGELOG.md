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
  detection of RAW, single-segment EWF/E01, native VHD and — through
  `qemu-img` — QCOW2/VMDK/VHDX; MBR, extended/EBR and GPT parsing with
  non-fatal warnings instead of hard failures.
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
- Documentation: architecture, user guide, security, legal, release.
- CI: GitHub Actions build/test/lint matrix for Linux, Windows, macOS.

[Unreleased]: https://github.com/IshikawaUta/gohex/compare/HEAD...HEAD
