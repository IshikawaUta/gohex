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

## Comparing documents

Toolbar → **Compare** byte-compares two open documents read-only and
lists every contiguous differing range with its offset and length — the
binary equivalent of WinHex's file compare, useful for spotting the one
edited sector in two disk images.

Pick A and B from the open tabs, press **Compare**: the summary reports
either "identical" or the first differing offset plus exact equal /
differing byte counts. Identical regions are skipped in 64 KiB blocks, so
comparing two multi-gigabyte images only pays byte-level cost inside the
blocks that actually differ. The range list is capped at 500 entries
(marked truncated) but the byte counts stay exact. Comparing a document
with itself is rejected; sizes may differ — bytes present in only one
document form a trailing differing range.

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

## Crash reports

Toolbar → **Crash report** parses the text/JSON reports that sit next to
memory captures in a triage workflow — read-only, never symbolicated:

| Format | Detection |
|---|---|
| macOS/iOS `.ips` | JSON header with `bug_type` + JSON body |
| Android `tombstone` | standard banner or build fingerprint + backtrace |
| Windows WER `Report.wer` | `EventType=` + report identifiers/signatures |

**Open report…** then **Parse** shows the structured summary: application,
version, timestamp, crash type (bug type / signal / event type), pid/tid,
frame count, the top frames exactly as written in the file, plus
format-specific details (exception signal, fault address, build
fingerprint, WER signatures, FILETIME converted to RFC 3339). A report
that is not one of the supported formats reports "unrecognized crash
report format" instead of guessing; files over 8 MiB are rejected. Every
parse is audited.

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

## Automation scripts

Toolbar → **Script** runs a Starlark (`.star`) script over the documents
you already have open — triage helpers, hash lists, pattern hunts — without
giving the script any way to touch the rest of the machine.

The sandbox is deliberately tiny: no filesystem, no network, no clock, no
randomness, and no `load()` of other modules. The only capability a script
receives is the built-in `gohex` module:

| Member | Meaning |
|---|---|
| `gohex.docs()` | list of open documents (`id`, `name`, `size`) |
| `gohex.read(id, offset, size)` | bytes from a document (a short read at the end is fine) |
| `gohex.find(id, text, offset=0, limit=100)` | offsets of an ASCII text search, up to `limit` (max 500) |
| `gohex.hash(data, algo="sha256")` | hex digest, same algorithms as the toolbar |
| `gohex.version()` | product + version string |

Example — scan every open document for MZ headers:

```python
for d in gohex.docs():
    hits = gohex.find(d.id, "MZ", limit=500)
    print("%s (%d bytes): %d MZ headers" % (d.name, d.size, len(hits)))
    if hits:
        head = gohex.read(d.id, hits[0], 2)
        print("  first at 0x%x: %r" % (hits[0], head))
```

Runs are bounded: a 30-second timeout, a one-million-step interpreter limit,
`print()` output capped at 1 MiB and a single `read` of at most 16 MiB — a
runaway script stops, it does not hang the UI. A script that fails (syntax
error, runtime error, limit hit) reports the error with the interpreter's
backtrace in the output pane, with everything `print()` wrote before the
failure preserved. Every run — success or failure — is recorded in the audit
log as a `script` event with the script's path, duration and outcome.

Scripts read the *open document*, including unsaved in-memory edits, not the
file on disk.

## Structure templates

Toolbar → **Template** overlays a named structure definition on the active
document — the WinHex template workflow for reading PE headers, partition
records, log entries or any other fixed-layout structure without guessing
offsets by hand.

Template files are plain text (`*.tpl`), WinHex-compatible in shape:

```
Template=DOS Header
Comment=First 64 bytes of a PE file

Offset=0
Type=u16
Name=e_magic
Description=Magic number

Offset=2
Type=u16[2]
Name=e_cblp

Offset=8
Type=string[8]
Name=e_res
```

Supported types: `u8/u16/u32/u64`, `i8/i16/i32/i64`, `f32/f64`,
`bytes[N]`, `string[N]` (alias `char[N]`), `guid` (16 bytes, Microsoft
mixed-endian layout), `filetime` (Windows FILETIME → UTC timestamp),
`unixtime` (u32 seconds → UTC) and `bool8/bool16/bool32`. Arrays use
`Type=u32[4]` or a separate `Count=4` key. `Endian=big` switches
multi-byte order for the whole template (GUIDs stay mixed-endian).
`Offset=` starts a new field; `Type` and `Name` are required per field.
Parsing is strict — an unknown key or type is refused, never skipped.

Open a document, load the template, set the **Offset** (or click **Cursor**
to reuse the hex view's cursor position) and **Apply**. Every field is
shown with its absolute offset and a formatted value: integers as hex plus
decimal, FILETIME and Unix times as UTC timestamps, GUIDs in the standard
`{xxxxxxxx-xxxx-…}` layout. A template whose span runs past the end of the
document is refused rather than half-filled. Loading and each apply are
recorded in the audit log; templates only ever read.

## Preferences (⚙ or `Ctrl+,`)

| Setting | Notes |
|---|---|
| Theme | light / dark (+ custom theme files) |
| Language | English / Bahasa Indonesia |
| Bytes per line | grid width (8/16/32/…) |
| Offset radix | hex or decimal display |
| Profile | editing policy, see above |
| Sandbox mode | simulate saves, never write |
| Keyboard shortcuts | rebind every action (see below) |

Saved to `~/.config/gohex/config.json` (platform user-config dir).

## Keyboard shortcuts

Stock bindings (WinHex-flavoured); every chord is configurable in
**Preferences → Keyboard shortcuts**:

| Key | Action | Action ID |
|---|---|---|
| `Ctrl+O` | Open file | `file.open` |
| `Ctrl+N` | New document | `file.new` |
| `Ctrl+S` / `Ctrl+Shift+S` | Save / Save as | `file.save` / `file.saveAs` |
| `Ctrl+Z` / `Ctrl+Y` | Undo / Redo | `edit.undo` / `edit.redo` |
| `Ctrl+C` / `Ctrl+Shift+C` | Copy as hex / as text | `edit.copy` / `edit.copyText` |
| `Ctrl+A` | Select all | `edit.selectAll` |
| `Ctrl+F` | Find panel | `search.find` |
| `Ctrl+G` | Go to offset | `goto.offset` |
| `Ctrl+,` | Preferences | `preferences.open` |
| `Esc` | Close dialog or find panel; clear pending nibble | — |
| Arrows / `Home` / `End` / `PgUp` / `PgDn` | Move cursor (grid focused) | — |
| `Backspace` | Cancel a half-typed nibble | — |

`Enter`/`Shift+Enter` inside the find field jump to next/previous match.

Rebinding: edit the chord in **Preferences** (`Ctrl+Alt+Shift+Key`;
aliases Control/Cmd/Option/Super are accepted and normalised on save).
Leaving a field empty unbinds the action. Invalid chords, unknown action
IDs and two actions claiming the same chord are rejected on save with the
reason — the same validation runs on the `shortcuts` map in
`config.json`, so a hand-edited file cannot smuggle in a broken keymap.
Actions shown as reserved (`search.replace`, `search.next`/`prev`,
`view.theme`, `help.shortcuts`) keep their bindings for future UI.

## Command-line companion

`gohex-cli` is a read-only companion binary — same engines as the GUI, no
write verbs:

```
gohex-cli hash   [-algo sha256] FILE            # md5, sha1, sha256, sha512, crc32, ...
gohex-cli info   FILE                           # size, container format, partition table
gohex-cli search [-hex "DE AD ?? EF" | -text foo] [-enc ascii|utf16le|utf16be] [-limit N] FILE
```

`FILE` may be a raw image or any container the GUI can open (E01/L01
multi-segment, VHD/QCOW2/VMDK/VHDX) — detection is magic-based. `-hex`
patterns support `??` wildcard pairs; `-text` searches for literal text in
the chosen encoding. `search` exits 3 when nothing matched (0 hit, 1 error,
2 usage). Output of `search` is tab-separated `0xOFFSET<TAB>LENGTH`.

## Updates

GoHex never phones home. The **About** dialog (toolbar `?`) has a **Check
for updates** button, and it only makes a network request when you have
opted in with `GOHEX_UPDATE_CHECK=1` — the request goes to the GoHex GitHub
releases endpoint (or `GOHEX_UPDATE_URL` if set), compares the latest
release tag with the running version and shows the result. A failed check
reports why; it never blocks anything else. Enabled checks are recorded in
the audit log.

## Environment variables

| Variable | Effect |
|---|---|
| `GOHEX_OPEN` | Comma-separated files to open at start |
| `GOHEX_SKIP_DISCLAIMER=1` | Pre-accept the disclaimer (tests/CI) |
| `GOHEX_THEME` / `GOHEX_LANG` / `GOHEX_PROFILE` | Override preferences |
| `GOHEX_ALLOW_UNSAFE_WRITE=1` | Enable physical-disk write capability |
| `GOHEX_UPDATE_CHECK=1` | Opt in to update checks (off by default) |
| `GOHEX_UPDATE_URL` | Override the update-check endpoint (mirrors, offline fixtures) |

## Audit log

Casework actions are appended to `~/.config/gohex/audit.jsonl` (mode `0600`,
one JSON object per line) — see [security.md](security.md).

## Limits & notes

- Files larger than 4 GB are supported (windowed reads, no full slurp).
- Copy operations are capped at 16 MiB per selection.
- Find-all returns at most 500 matches per query.
- The CLI (`cmd/gohex-cli`) provides read-only `hash`, `info` and `search`
  (see below); write paths live in the GUI only.
