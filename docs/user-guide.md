# GoHex user guide

GoHex is a cross-platform hex editor with forensic-grade defaults: **read-only
until you deliberately allow editing**, full undo/redo, hashing, and an audit
log for casework.

## Install & run

```bash
# Prerequisites: Go ≥ 1.25, Node.js ≥ 20, and WebView dev libraries
#   Linux:   sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config
#   Windows: WebView2 Runtime + MinGW-w64 (CGO)
#   macOS:   Xcode Command Line Tools

git clone https://github.com/IshikawaUta/gohex && cd gohex

# Development run
npm --prefix frontend run build && go run .

# Production binary (embeds the frontend)
wails3 build          # → bin/gohex
./bin/gohex
```

Open a file at launch:

```bash
./bin/gohex evidence.dd          # command-line argument
GOHEX_OPEN=a.bin,b.bin ./bin/gohex   # comma-separated (used by tests/CI)
```

On first start an ethics disclaimer is shown; accept it once (stored locally).
Tests/CI can pre-accept with `GOHEX_SKIP_DISCLAIMER=1`.

## The window

```
┌ toolbar ────────────────────────────────────────────────────┐
│ Open New Save SaveAs │ Undo Redo Find │ Encoding Theme Hash │ ⚙ ? │
├ tab bar ────────────────────────────────────────────────────┤
│ [sampleA.bin ✕] [+]                                          │
├ find panel (Ctrl+F, optional) ───────────────────────────────┤
├ hex grid ────────────────────────────────────────────────────┤
│ 00000000  47 6F 48 65 78 …          GoHex …                 │
├ status bar ──────────────────────────────────────────────────┤
│ offset/goto field · selection · size · encoding              │
└──────────────────────────────────────────────────────────────┘
```

- **Hex grid**: click a nibble to place the cursor; type `0`–`f` to overwrite
  bytes (two nibbles per byte); drag to select; right-click for a context menu
  (copy offset/hex/text, select all, delete selection).
- **Goto**: press `Ctrl+G` or click the offset field in the status bar, type an
  offset (`0x100`, `256`, …), press `Enter`.
- **Tabs**: each open file is a tab. `+`/`Ctrl+N` creates an empty document;
  `×` or middle-click closes a tab.

## Editing & saving

- Editing depends on the **profile** (⚙ → Profile):
  - `readonly` — all modification attempts are rejected.
  - `analyst` (default) — edit documents, save to new files.
  - `recovery`, `examiner` — see [architecture.md](architecture.md).
- `Ctrl+Z` / `Ctrl+Y` undo/redo (journal-backed; undoing back to the save
  point marks the document clean).
- `Ctrl+S` saves, `Ctrl+Shift+S` save-as. Dirty files show a dot in the tab
  and title.
- **Sandbox mode** (Preferences) simulates saves without touching the disk.
- Physical-disk writes (stage 2+) require all of: explicit
  `GOHEX_ALLOW_UNSAFE_WRITE=1`, a two-step confirmation, and an audit entry.

## Search & replace

`Ctrl+F` opens the find panel:

- Modes: **text** (with `Aa` case toggle), **hex** (`4D 5A 90`), **regex**.
- `Enter` / `Shift+Enter` find next/previous; `wrap` restarts at the edges.
- ☰ finds all (up to 500 matches, shown as clickable chips).
- Replace-all needs editing permission and asks for confirmation; the change
  is undoable with `Ctrl+Z`.

## Hashing

Toolbar → **Hash…** computes a checksum of the active document; the result
appears in the status bar (`SHA-256: …`). The list includes *file* hashes
(sha256/sha512/sha1/md5/crc32/crc32c/blake3/xxhash64) and *selection* variants.

## Disk images & file systems

Toolbar → **Disk** opens the disk-image browser and walks a medium
read-only.

1. **Open image…** selects the container (RAW, E01, L01, VHD, QCOW2,
   VMDK, VHDX — `qemu-img` is needed for the last three). For multi-segment
   E01/L01 sets it does not matter which segment you pick; GoHex finds the
   rest by naming convention.
2. MBR/GPT partitions are listed automatically; pick one to browse, or
   browse the whole medium when the image has no partition table.
3. Click through directories like a file manager; select a file to
   **Export file…** (written to a new path, SHA-256 recorded in the audit
   log) or **Open as hex** to load its bytes into the editor.

Supported file systems: FAT12/16/32, exFAT, NTFS, ext2/3/4, ISO9660 (Rock
Ridge names where present), HFS+/HFSX and APFS. Name lookups follow the
volume's own rules — HFS+ honours the catalogue key-compare type, APFS
honours its case-insensitive incompat flag — and APFS mounts the newest
valid checkpoint of its single volume. Files that GoHex cannot honestly
decode are *flagged, never guessed*: `compressed` (HFS+ decmpfs),
`encrypted` (sealed APFS volumes), `hardlink`, `symlink` and `readonly`
appear as attributes on the entry.

## Memory captures & crash dumps

Toolbar → **Memory** inspects RAM captures and crash dumps read-only. The
first time you open it you must acknowledge an ethics notice: this module is
for authorized examination only, and it never extracts credentials or live
process data.

1. **Open capture…** selects the file. GoHex recognises LiME v1 captures
   (`EMiL` magic, physical ranges), AVML v2 captures (`AVML` magic, physical
   ranges stored as Snappy-framed compressed blocks), Linux ELF core dumps
   (virtual `PT_LOAD` ranges), Windows minidumps (virtual ranges from the
   memory streams) and Windows 64-bit crash dumps (`PAGEDU64`: complete
   dumps with physical runs, and bitmap dumps whose set pages are mapped);
   a headerless dump opens as a single segment without an address map.
2. The segment table lists every range: its start–end address, byte length
   and file offset (virtual offset for compressed captures). Select a row to
   **Open segment as hex**, or **Open capture as hex** for the whole file.
   AVML captures are decompressed on the fly — the hex view always shows
   uncompressed bytes.
3. Type an **Address** (decimal or `0x…` hex) and **Locate** to map it onto
   the file offset holding that byte; **Open at address** loads the editor
   window from there to the end of its segment. Addresses are physical for
   LiME, AVML and Windows dumps and virtual for cores and minidumps —
   always use the dump's own address space.

Everything is strictly read-only — the capture is never modified, and a
truncated dump is clamped to the bytes that exist. Gaps between segments
(all-zero pages elided by AVML writers, pages absent from a Windows dump
bitmap) are not part of the map and report "not covered". 32-bit Windows
dumps (`PAGEDUMP`), Windows kernel and small memory dumps, and Windows 8+
compressed kernel dumps are not yet supported and report an explicit error
(future work).

## Carving

Toolbar → **Carve** recovers files that are no longer reachable through a
directory — deleted, orphaned, or living in an image whose file system you
cannot mount.

1. **Open image…** selects the evidence (any container GoHex can read: RAW,
   E01, L01, VHD, QCOW2, VMDK, VHDX, or a plain file).
2. Optionally narrow **From** / **To** (decimal or `0x…` hex) to a single
   partition instead of the whole medium.
3. Toggle the types to look for. `⌁` types end at a footer (JPEG, PNG, GIF,
   PDF, ZIP); `⌘` types declare their own size (BMP, WAV, AVI, MP4).
4. **Scan** lists every candidate whose size it can prove, with offset and
   length, while progress runs in the status bar.

Select a row to **Export…** it (written to a new file, SHA-256 recorded in the
audit log) or **Open as hex** to inspect the recovered bytes in place.

*Include truncated candidates* also reports objects whose terminator lies past
the scanned range. Leave it off unless you know the image is cut short — most
such hits are false positives. Recovery is best-effort: a file whose header and
footer were both overwritten cannot be brought back.

## Browser artifacts

Toolbar → **Browser** reads browsing artefacts out of the profiles GoHex finds
on disk. The first time you open it you must acknowledge an ethics notice:
this module is for authorized examination only, and it never reads credentials,
cookies, autofill or form data.

1. **Home root** defaults to your own home directory; **Choose home…** points
   it elsewhere — for example a mounted evidence image with a `home/` tree.
2. **Rescan** lists every profile found (Chrome/Chromium/Edge/Brave,
   Firefox, Safari) and **Read profile** loads it.
3. The **History**, **Downloads** and **Bookmarks** tabs each carry their own
   counts and a **Filter…** box.
4. **Export…** writes the visible tab as CSV or JSON; the file is created new
   (never overwritten), its SHA-256 is recorded in the audit log, and it
   carries the profile path and any warnings in its header or JSON envelope.

Some profiles are reported with warnings rather than failing outright — a
Firefox profile without an annotation, or a Safari database whose title column
is missing, still yields everything else. Read-only: no database is modified,
checkpointed or repaired.

## Case management & reports

Toolbar → **Case** keeps the record of an investigation: what you examined,
what it hashed to, what you concluded, and a timeline of events. The case
itself is an ordinary JSON file — diff it, review it, archive it — and it
never copies evidence around: it records the path, size and SHA-256 of each
file, which is what chain of custody needs.

1. **Name** the case, add an examiner and a description, then **New case**.
   **Open case…** loads an existing `.json` case file instead.
2. **Evidence → Add evidence…** takes one or more files (an image, a carved
   object, an export). Each is streamed through SHA-256 and recorded; the
   same file twice is refused.
3. **Verify** re-hashes one file against the digest recorded when it was
   added; **Verify all** does the whole list and reports how many matched.
   A changed file is reported as `MISMATCH` and written to the audit log as
   a failed integrity check — it is the finding, not a crash.
4. **Findings → Add finding** records a conclusion with a severity and an
   optional link to the evidence it rests on.
5. **Timeline → Add event** adds one point (time, kind, source, summary),
   shown oldest first, with undated entries last.
6. **Save case…** writes the JSON file (created new or updated in place,
   mode `0600`, SHA-256 recorded in the audit log).
7. **Export report…** renders HTML or JSON to a file that must not already
   exist. The report carries the case summary, evidence table with full
   digests, findings and timeline, plus a checksum over the canonical JSON of
   the case so a reader can prove which case it describes.

Only one case is open at a time; **Close** releases it. Closing without
saving discards unsaved findings, and that too is recorded in the audit log.

## Preferences (⚙ or `Ctrl+,`)

| Setting | Notes |
|---|---|
| Theme | light / dark (+ custom theme files) |
| Language | English / Bahasa Indonesia |
| Bytes per line | grid width (8/16/32/…) |
| Offset radix | hex or decimal display |
| Profile | editing policy, see above |
| Sandbox mode | simulate saves, never write |

Saved to `~/.config/gohex/config.json` (platform user-config dir).

## Keyboard shortcuts (Stage 1)

| Key | Action |
|---|---|
| `Ctrl+O` | Open file |
| `Ctrl+N` | New document |
| `Ctrl+S` / `Ctrl+Shift+S` | Save / Save as |
| `Ctrl+Z` / `Ctrl+Y` | Undo / Redo |
| `Ctrl+F` | Find panel |
| `Ctrl+G` | Go to offset |
| `Ctrl+A` | Select all |
| `Ctrl+C` / `Ctrl+Shift+C` | Copy as hex / as text |
| `Ctrl+,` | Preferences |
| `Esc` | Close dialog or find panel; clear pending nibble |
| Arrows / `Home` / `End` / `PgUp` / `PgDn` | Move cursor (grid focused) |
| `Backspace` | Cancel a half-typed nibble |

`Enter`/`Shift+Enter` inside the find field jump to next/previous match.
The `shortcuts` map in `config.json` is reserved for the configurable keymap
engine planned for stage 5.

## Environment variables

| Variable | Effect |
|---|---|
| `GOHEX_OPEN` | Comma-separated files to open at start |
| `GOHEX_SKIP_DISCLAIMER=1` | Pre-accept the disclaimer (tests/CI) |
| `GOHEX_THEME` / `GOHEX_LANG` / `GOHEX_PROFILE` | Override preferences |
| `GOHEX_ALLOW_UNSAFE_WRITE=1` | Enable physical-disk write capability |
| `GOHEX_UPDATE_CHECK=1` | Opt in to update checks (off by default) |

## Audit log

Casework actions are appended to `~/.config/gohex/audit.jsonl` (mode `0600`,
one JSON object per line) — see [security.md](security.md).

## Limits & notes

- Files larger than 4 GB are supported (windowed reads, no full slurp).
- Copy operations are capped at 16 MiB per selection.
- Find-all returns at most 500 matches per query.
- The CLI (`cmd/gohex-cli`) is on the roadmap (stage 5); Stage 1 is GUI-only.
