<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg, fromBase64, Events } from "../api";
  import * as A from "../actions";
  import type {
    DiskLayout,
    FileSystemInfo,
    ImageInfo,
    SaveResult,
    CloneJobStatus,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";
  import type { Entry, Stream } from "../../../bindings/github.com/IshikawaUta/gohex/internal/fs/models";

  let path = $state("");
  let image = $state<ImageInfo | null>(null);
  let layout = $state<DiskLayout | null>(null);
  let sel = $state(-1);
  let fsInfo = $state<FileSystemInfo | null>(null);
  let dir = $state("/");
  let entries = $state<Entry[]>([]);
  let selectedPath = $state("");
  let preview = $state("");
  let busy = $state(false);
  let error = $state("");

  // NTFS alternate data streams.
  let adsStreams = $state<Stream[]>([]);
  let adsOpen = $state(false);

  // Clone v2 state.
  let cloneOpen = $state(false);
  let cloneCompress = $state("none");
  let cloneSplit = $state(0);
  let cloneResume = $state(false);
  let cloneBadLog = $state("");
  let cloneJob = $state<CloneJobStatus | null>(null);
  let cloneBusy = $state(false);

  let parts = $derived(layout?.partitions ?? []);
  let selected = $derived(sel >= 0 && sel < parts.length ? parts[sel] : null);
  let fsOffset = $derived(selected ? selected.partition.start : 0);
  let fsSize = $derived(selected ? selected.partition.size : 0);
  let crumbs = $derived(dir.split("/").filter((c) => c.length > 0));
  let clonePct = $derived(
    cloneJob && cloneJob.total > 0 ? Math.floor((cloneJob.copied * 100) / cloneJob.total) : 0,
  );

  let unsub: (() => void) | null = null;
  onMount(() => {
    unsub = Events.On("clone:progress", (ev) => {
      const d = ev.data as CloneJobStatus | null;
      if (d && d.id === cloneJob?.id) cloneJob = d;
    });
    const done = Events.On("clone:done", (ev) => {
      const d = ev.data as CloneJobStatus | null;
      if (d && d.id === cloneJob?.id) {
        cloneJob = d;
        cloneBusy = false;
        if (d.state === "done") {
          flash(`Clone done: ${d.copied} bytes, ${d.badSectors} bad sectors`);
        } else if (d.state === "error") {
          error = d.error ?? "clone failed";
        }
      }
    });
    const prev = unsub;
    unsub = () => {
      prev?.();
      done();
    };
  });
  onDestroy(() => unsub?.());

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open disk image",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (target) await load(target);
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function startClone(): Promise<void> {
    if (!path) return;
    let dst: string;
    try {
      const res = await Dialogs.SaveFile({
        Title: "Clone destination",
        Filename: `${path.split("/").pop() ?? "clone"}.img`,
      });
      dst = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    if (cloneCompress !== "none" && !dst.endsWith(".gz") && !dst.endsWith(".zst")) {
      dst += cloneCompress === "gzip" ? ".gz" : ".zst";
    }
    cloneBusy = true;
    error = "";
    cloneJob = null;
    try {
      cloneJob = await svc.StartClone({
        srcPath: path,
        dstPattern: dst,
        compression: cloneCompress,
        splitSize: cloneSplit,
        resume: cloneResume,
        badSectorLog: cloneBadLog,
      });
      flash("Clone started");
    } catch (e) {
      error = errMsg(e);
      cloneBusy = false;
    }
  }

  async function cancelClone(): Promise<void> {
    if (!cloneJob) return;
    try {
      await svc.CancelClone(cloneJob.id);
    } catch (e) {
      error = errMsg(e);
    }
  }

  async function load(p: string): Promise<void> {
    busy = true;
    error = "";
    preview = "";
    path = p;
    try {
      image = await svc.ProbeImage(p);
      layout = await svc.Partitions(p);
      sel = -1;
      fsInfo = null;
      entries = [];
      selectedPath = "";
      if (parts.length === 0) {
        // Superfloppy: a single filesystem with no partition table.
        await selectPartition(-1);
      }
    } catch (e) {
      image = null;
      layout = null;
      path = "";
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function selectPartition(i: number): Promise<void> {
    sel = i;
    entries = [];
    selectedPath = "";
    preview = "";
    fsInfo = null;
    if (!path) return;
    busy = true;
    try {
      try {
        fsInfo = await svc.ProbeFileSystem(path, fsOffset, fsSize);
      } catch {
        fsInfo = null; // "nothing recognised here" is not an error
      }
      if (fsInfo) await list("/");
    } finally {
      busy = false;
    }
  }

  async function list(d: string): Promise<void> {
    if (!fsInfo || !path) return;
    busy = true;
    error = "";
    try {
      entries = (await svc.FsList(path, fsOffset, fsSize, d)) ?? [];
      dir = d;
      selectedPath = "";
      preview = "";
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function activate(entry: Entry): Promise<void> {
    if (entry.dir) {
      await list(entry.path);
      return;
    }
    selectedPath = entry.path;
    preview = "";
    try {
      const b64 = await svc.FsRead(path, fsOffset, fsSize, entry.path, 0, 4096);
      preview = b64 ? hexDump(b64) : "";
    } catch (e) {
      error = errMsg(e);
    }
  }

  function goUp(): void {
    const up = "/" + crumbs.slice(0, -1).join("/");
    void list(up === "/" ? "/" : up);
  }

  async function openAsHex(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    try {
      const doc = selected
        ? await svc.OpenRange(path, selected.partition.start, selected.partition.size)
        : await svc.OpenImage(path);
      store.activeId = doc.id;
      await A.refreshDocs();
      A.syncSelectionFromDoc();
      store.showDisk = false;
      flash(`${doc.name} — ${doc.size} bytes`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportSelected(): Promise<void> {
    if (!path || !selectedPath) return;
    const name = selectedPath.split("/").pop() ?? "file.bin";
    let dst: string;
    try {
      dst = (await Dialogs.SaveFile({ Title: "Export file", Filename: name })) as string;
    } catch (e) {
      error = `Export dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const res: SaveResult = await svc.FsExport(path, fsOffset, fsSize, selectedPath, dst);
      flash(`Exported ${res.bytesSaved} bytes → ${res.path} (sha256:${res.sha256})`);
      store.showDisk = false;
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function hexDump(b64: string, max = 512): string {
    const bytes = fromBase64(b64).subarray(0, max);
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.subarray(i, i + 16);
      const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
      lines.push(`${i.toString(16).padStart(8, "0")}  ${hex}`);
    }
    return lines.join("\n");
  }

  let selectedEntry = $derived(entries.find((e) => e.path === selectedPath) ?? null);
  let canStreams = $derived(
    fsInfo?.type === "ntfs" && !!selectedEntry && !selectedEntry.dir,
  );

  async function loadStreams(): Promise<void> {
    if (!path || !selectedPath) return;
    busy = true;
    error = "";
    try {
      adsStreams = (await svc.FsStreams(path, fsOffset, fsSize, selectedPath)) ?? [];
      adsOpen = true;
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function openStream(s: Stream): Promise<void> {
    busy = true;
    error = "";
    try {
      await svc.FsOpenStream(path, fsOffset, fsSize, selectedPath, s.name);
      flash(`Opened stream ${s.path} (${fmtSize(s.size)}) read-only`);
      store.showDisk = false;
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportStream(s: Stream): Promise<void> {
    let dst: string;
    try {
      dst = (await Dialogs.SaveFile({
        Title: "Export alternate stream",
        Filename: s.path.replace(/:/g, "_"),
      })) as string;
    } catch (e) {
      error = `Export dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const res: SaveResult = await svc.FsStreamExport(
        path,
        fsOffset,
        fsSize,
        selectedPath,
        s.name,
        dst,
      );
      flash(`Exported ${res.bytesSaved} bytes → ${res.path} (sha256:${res.sha256})`);
      store.showDisk = false;
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function fmtSize(n: number): string {
    if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)} GiB`;
    if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(2)} MiB`;
    if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
    return `${n} B`;
  }

  function fmtOffset(n: number): string {
    return `0x${n.toString(16).toUpperCase().padStart(8, "0")}`;
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Disk image browser"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showDisk = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showDisk = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Disk image</h2>
      <button class="primary" onclick={choose}>Open image…</button>
    </div>

    {#if image}
      <p class="meta">
        <span class="mono path">{image.path}</span>
        <span class="tag">{image.format.toUpperCase()}</span>
        <span>{fmtSize(image.size)}</span>
        <span class="dim">{image.size} bytes</span>
      </p>
    {/if}

    {#if layout}
      {#if layout.warnings?.length}
        <ul class="warn">
          {#each layout.warnings as w (w)}
            <li>{w}</li>
          {/each}
        </ul>
      {/if}

      <table>
        <thead>
          <tr><th>#</th><th>Type</th><th>Start</th><th>Size</th><th>File system</th><th>Label</th></tr>
        </thead>
        <tbody>
          {#if parts.length === 0}
            <tr class="none">
              <td colspan="6">No partition table — the whole image is one volume</td>
            </tr>
          {/if}
          {#each parts as p, i (p.partition.index)}
            <tr class:selected={sel === i} class="click" onclick={() => void selectPartition(i)}>
              <td>{p.partition.index}</td>
              <td>{p.partition.name}{p.partition.bootable ? " ·boot" : ""}</td>
              <td class="mono">{fmtOffset(p.partition.start)}</td>
              <td>{fmtSize(p.partition.size)}</td>
              <td>{p.filesystem || "—"}</td>
              <td>{p.fsLabel || "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>

      <div class="actions">
        <button class="primary" onclick={openAsHex} disabled={busy || !path}>
          {selected ? "Open partition as hex" : "Open image as hex"}
        </button>
        <button onclick={() => (cloneOpen = !cloneOpen)} disabled={!path} title="Forensic disk clone: compress, split, resume, bad-sector log">
          {cloneOpen ? "Hide clone ▲" : "Clone image… ▼"}
        </button>
      </div>

      {#if cloneOpen && path}
        <div class="clone">
          <div class="clone-row">
            <label class="field">
              <span>Compression</span>
              <select bind:value={cloneCompress} disabled={cloneBusy}>
                <option value="none">none (raw, SHA-256 verified)</option>
                <option value="gzip">gzip</option>
                <option value="zstd">zstd</option>
              </select>
            </label>
            <label class="field">
              <span>Split (bytes, 0 = off)</span>
              <input type="number" bind:value={cloneSplit} min="0" disabled={cloneBusy || cloneCompress !== "none"} />
            </label>
            <label class="field" title="Continue an interrupted run from its state file">
              <input type="checkbox" bind:checked={cloneResume} disabled={cloneBusy || cloneCompress !== "none"} />
              <span>Resume</span>
            </label>
            <label class="field grow">
              <span>Bad-sector log</span>
              <input bind:value={cloneBadLog} placeholder="bad-sectors.log (optional)" disabled={cloneBusy} />
            </label>
          </div>
          <div class="clone-row">
            {#if cloneBusy && cloneJob}
              <div class="progress" role="progressbar" aria-valuenow={clonePct} aria-valuemin={0} aria-valuemax={100}>
                <div class="bar" style="width: {clonePct}%"></div>
              </div>
              <span class="mono">{clonePct}% · {fmtSize(cloneJob.copied)} / {fmtSize(cloneJob.total)} · bad {cloneJob.badSectors}</span>
              <button class="danger" onclick={() => void cancelClone()}>Cancel</button>
            {:else}
              <button class="primary" onclick={() => void startClone()} disabled={busy || !path}>
                Start clone ▶
              </button>
              {#if cloneJob?.state === "done"}
                <span class="dim">Done: {fmtSize(cloneJob.copied)}, {cloneJob.badSectors} bad sectors</span>
              {:else if cloneJob?.state === "cancelled"}
                <span class="warn">Cancelled at {fmtSize(cloneJob.copied)} — tick Resume to continue.</span>
              {/if}
            {/if}
          </div>
          <p class="dim clone-note">
            Source is opened read-only; the destination is verified with
            SHA-256 end to end (compression=none). Unreadable sectors are
            zero-filled and logged. Resume only works for uncompressed clones.
          </p>
        </div>
      {/if}

      {#if fsInfo}
        <div class="fshead">
          <span class="tag">{fsInfo.type.toUpperCase()}</span>
          {#if fsInfo.label}<span>{fsInfo.label}</span>{/if}
          <span class="dim">{fmtSize(fsInfo.size)} at {fmtOffset(fsInfo.offset)}</span>
        </div>

        <nav class="crumbs">
          <button class="crumb" onclick={() => void list("/")}>/</button>
          {#each crumbs as c, i (i)}
            <button class="crumb" onclick={() => void list("/" + crumbs.slice(0, i + 1).join("/"))}>
              {c}
            </button>
          {/each}
          <span class="spacer"></span>
          {#if crumbs.length}
            <button class="crumb" onclick={goUp}>↑ up</button>
          {/if}
        </nav>

        <div class="browser">
          <ul class="entries">
            {#each entries as e (e.path)}
              <li>
                <button
                  class="entry"
                  class:sel={selectedPath === e.path}
                  onclick={() => void activate(e)}
                >
                  <span class="ico">{e.dir ? "▸" : e.deleted ? "✕" : "·"}</span>
                  <span class="name">{e.name}</span>
                  <span class="dim">{e.dir ? "" : fmtSize(e.size)}</span>
                </button>
              </li>
            {:else}
              <li class="dim empty">Empty directory</li>
            {/each}
          </ul>

          <div class="side">
            {#if preview}
              <pre class="dump">{preview}</pre>
            {:else}
              <p class="dim">Select a file to preview its first bytes.</p>
            {/if}
            <button class="primary" onclick={exportSelected} disabled={busy || !selectedPath}>
              Export file…
            </button>
            {#if canStreams}
              <button onclick={() => void loadStreams()} disabled={busy}>
                Alternate streams…
              </button>
            {/if}
            {#if adsOpen}
              <div class="ads">
                <div class="adshead">
                  <span>ADS of {selectedEntry?.name}</span>
                  <button class="crumb" onclick={() => (adsOpen = false)}>✕</button>
                </div>
                {#if adsStreams.length}
                  <ul class="entries">
                    {#each adsStreams as s (s.name)}
                      <li>
                        <div class="adsrow">
                          <span class="name" title={s.path}>{s.name}</span>
                          <span class="dim">{fmtSize(s.size)}</span>
                          {#if s.resident}<span class="tag">R</span>{/if}
                          {#if s.compressed}<span class="tag">C</span>{/if}
                          {#if s.encrypted}<span class="tag">E</span>{/if}
                          <button
                            class="crumb"
                            disabled={busy || s.compressed || s.encrypted}
                            onclick={() => void openStream(s)}
                            title="Open this stream in the hex editor"
                          >
                            Open
                          </button>
                          <button
                            class="crumb"
                            disabled={busy || s.compressed || s.encrypted}
                            onclick={() => void exportStream(s)}
                            title="Export this stream to a file"
                          >
                            Export…
                          </button>
                        </div>
                      </li>
                    {/each}
                  </ul>
                {:else}
                  <p class="dim">No named streams on this file.</p>
                {/if}
              </div>
            {/if}
          </div>
        </div>
      {:else if parts.length}
        <p class="dim">No recognised file system in the selected range.</p>
      {/if}
    {/if}

    {#if error}<p class="error">{error}</p>{/if}
    {#if busy}<p class="dim">Working…</p>{/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 90;
  }

  .modal {
    width: min(880px, 94vw);
    max-height: 88vh;
    overflow: auto;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 12px;
  }

  h2 {
    margin: 0;
    font-size: 18px;
    letter-spacing: 0.02em;
  }

  .meta {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin: 0 0 12px;
    font-size: 12.5px;
    color: var(--text-dim);
  }

  .path {
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 58ch;
  }

  .tag {
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 2px 6px;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
  }

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 12.5px;
  }

  th {
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-dim);
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  tr.click {
    cursor: pointer;
  }

  tr.click:hover td {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }

  tr.selected td {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
  }

  tr.none td {
    color: var(--text-dim);
    font-style: italic;
  }

  .warn {
    margin: 8px 0;
    padding-left: 18px;
    font-size: 11.5px;
    color: #d8a657;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin: 12px 0;
  }

  .clone {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 12px;
  }
  .clone-row {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }
  .clone-row .field {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }
  .clone-row .field.grow {
    flex: 1;
    min-width: 200px;
  }
  .clone-note {
    margin: 0;
    font-size: 11.5px;
  }
  .progress {
    flex: 1;
    min-width: 160px;
    height: 10px;
    background: var(--bg-hover, rgba(127, 127, 127, 0.2));
    border-radius: 5px;
    overflow: hidden;
  }
  .progress .bar {
    height: 100%;
    background: var(--accent, #4a9eff);
    transition: width 0.15s linear;
  }
  .danger {
    background: #a4262c;
    border: none;
    color: #fff;
    padding: 5px 12px;
    border-radius: 6px;
    cursor: pointer;
  }

  .fshead {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12.5px;
    margin-bottom: 8px;
  }

  .crumbs {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }

  .crumb {
    font-family: var(--font-mono);
    font-size: 12px;
    padding: 2px 6px;
  }

  .spacer {
    flex: 1;
  }

  .browser {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    min-height: 220px;
  }

  .entries {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 6px;
    max-height: 300px;
    overflow: auto;
  }

  .entry {
    display: grid;
    grid-template-columns: 16px 1fr auto;
    gap: 8px;
    width: 100%;
    text-align: left;
    font-size: 12.5px;
    padding: 4px 8px;
  }

  .entry.sel {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
  }

  .entry .name {
    font-family: var(--font-mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .ico {
    color: var(--text-dim);
  }

  .side {
    display: flex;
    flex-direction: column;
    gap: 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
  }

  .dump {
    margin: 0;
    font-family: var(--font-mono);
    font-size: 11px;
    line-height: 1.45;
    white-space: pre;
    overflow: auto;
    max-height: 240px;
    flex: 1;
  }

  .empty {
    padding: 10px;
    font-size: 12.5px;
  }

  .ads {
    border-top: 1px solid var(--border);
    padding-top: 8px;
    max-height: 200px;
    overflow: auto;
  }

  .adshead {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 12px;
    margin-bottom: 6px;
  }

  .adsrow {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 2px 0;
  }

  .adsrow .name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--font-mono);
  }

  .error {
    margin: 10px 0 0;
    font-size: 12px;
    color: #e07b7b;
  }
</style>
