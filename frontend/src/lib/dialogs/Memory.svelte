<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import * as A from "../actions";
  import type {
    Capture,
    Location,
    StackFrame,
    ModuleDiff,
    Thread,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/memory/models";

  let path = $state("");
  let cap = $state<Capture | null>(null);
  let sel = $state(-1);
  let physText = $state("");
  let located = $state<Location | null>(null);
  let busy = $state(false);
  let error = $state("");
  let tab = $state<"segments" | "triage">("segments");
  let frames = $state<StackFrame[]>([]);
  let stackThread = $state<number | null>(null);
  let diff = $state<ModuleDiff | null>(null);
  let diffPath = $state("");
  let extractAddr = $state("");
  let extractLen = $state("");

  let segments = $derived(cap?.segments ?? []);
  let details = $derived(cap?.details ?? null);
  let selected = $derived(sel >= 0 && sel < segments.length ? segments[sel] : null);
  let offsetLabel = $derived(cap?.compressed ? "virtual offset" : "file offset");
  let hasTriage = $derived(!!(details || cap?.bugCheck || cap?.hiber));

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open memory capture",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (!target) return;
      path = target;
      await load();
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function load(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    located = null;
    sel = -1;
    frames = [];
    stackThread = null;
    diff = null;
    diffPath = "";
    tab = "segments";
    try {
      cap = await svc.MemoryInfo(path);
      flash(
        `${cap.format.toUpperCase()} capture — ${segments.length} segment${segments.length === 1 ? "" : "s"}, ${fmtSize(cap.size)}`,
      );
    } catch (e) {
      cap = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function walkStack(tid: number | undefined): Promise<void> {
    if (!path || tid == null) return;
    busy = true;
    error = "";
    try {
      frames = (await svc.MemoryStack(path, tid)) ?? [];
      stackThread = tid;
      flash(`Thread ${tid} — ${frames.length} frame${frames.length === 1 ? "" : "s"} (frame-pointer walk)`);
    } catch (e) {
      frames = [];
      stackThread = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function extractRegion(addr: number, length: number): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    try {
      const res = await Dialogs.SaveFile({
        Title: "Extract memory region",
        Filename: `mem_${fmtAddr(addr).replace(/^0x/, "")}.bin`,
      });
      const dst = (Array.isArray(res) ? res[0] : res) as string | undefined;
      if (!dst) return;
      const n = await svc.MemoryDumpRange(path, addr, length, dst);
      flash(`Extracted ${fmtSize(n)} → ${dst}`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function compareWith(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    try {
      const res = await Dialogs.OpenFile({
        Title: "Compare loaded modules with…",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
      });
      const other = Array.isArray(res) ? res[0] : res;
      if (!other) return;
      diffPath = other;
      diff = await svc.MemoryCompareModules(path, other);
      flash(`Module diff — ${diff.common} common, ${(diff.onlyA ?? []).length} only in A, ${(diff.onlyB ?? []).length} only in B`);
    } catch (e) {
      diff = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function extractFromFields(): void {
    try {
      const addr = parseNum(extractAddr);
      const len = parseNum(extractLen);
      void extractRegion(addr, len);
    } catch (e) {
      error = errMsg(e);
    }
  }

  function parseNum(raw: string): number {
    const text = raw.trim();
    if (!text) throw new Error("Enter an address, e.g. 0x1000");
    const base = /^0[xX]/.test(text) ? 16 : 10;
    const n = parseInt(base === 16 ? text.slice(2) : text, base);
    if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
      throw new Error(`"${raw}" is not a valid address`);
    }
    return n;
  }

  async function locate(): Promise<void> {
    if (!path || !cap?.hasMap) return;
    busy = true;
    error = "";
    try {
      const phys = parseNum(physText);
      located = await svc.MemoryLocate(path, phys);
      sel = located.segment;
      flash(`${fmtAddr(phys)} → ${offsetLabel} ${fmtOffset(located.offset)}`);
    } catch (e) {
      located = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function openWindow(offset: number, size: number): Promise<void> {
    if (!path || !cap) return;
    busy = true;
    error = "";
    try {
      // Compressed captures (AVML) go through MemoryOpen, which presents
      // the uncompressed virtual view; everything else is a plain range.
      const doc = cap.compressed
        ? await svc.MemoryOpen(path, offset, size)
        : await svc.OpenRange(path, offset, size);
      store.activeId = doc.id;
      await A.refreshDocs();
      A.syncSelectionFromDoc();
      store.showMemory = false;
      flash(`${doc.name} — ${doc.size} bytes`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function openWhole(): void {
    if (!cap) return;
    // size 0 means "to the end" for both service calls.
    void openWindow(0, 0);
  }

  function openSelected(): void {
    if (!selected) return;
    void openWindow(selected.offset, selected.length);
  }

  function openLocated(): void {
    if (!located) return;
    const seg = segments[located.segment];
    if (!seg) return;
    void openWindow(located.offset, seg.offset + seg.length - located.offset);
  }

  function regLabel(t: Thread, ...keys: string[]): string {
    for (const k of keys) {
      const v = t.registers?.[k];
      if (v != null) return fmtAddr(v);
    }
    return "—";
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

  function fmtAddr(n: number): string {
    return `0x${n.toString(16).toUpperCase().padStart(12, "0")}`;
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Memory capture viewer"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showMemory = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showMemory = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Memory</h2>
      <button class="primary" onclick={choose}>Open capture…</button>
    </div>

    {#if path}
      <p class="meta"><span class="mono path">{path}</span></p>
    {/if}

    {#if cap}
      <div class="options">
        <span class="badge">{cap.format.toUpperCase()}</span>
        <span class="dim">{fmtSize(cap.size)}</span>
        <span class="dim">
          {cap.hasMap ? "address map" : "no address map — headerless dump"}
        </span>
        {#if cap.compressed}
          <span class="dim">Snappy-compressed — decompressed on the fly</span>
        {/if}
        <span class="spacer"></span>
        {#if cap.hasMap}
          <label class="field">
            <span>Address</span>
            <input
              class="mono"
              placeholder="0x1000"
              bind:value={physText}
              onkeydown={(e) => {
                if (e.key === "Enter") void locate();
              }}
            />
          </label>
          <button onclick={() => void locate()} disabled={busy}>Locate</button>
          {#if located}
            <span class="mono dim">{fmtOffset(located.offset)}</span>
            <button class="primary" onclick={openLocated} disabled={busy}>Open at address</button>
          {/if}
        {/if}
      </div>
    {/if}

    {#if cap && hasTriage}
      <div class="tabs" role="tablist" aria-label="Capture views">
        <button
          role="tab"
          aria-selected={tab === "segments"}
          class:active={tab === "segments"}
          onclick={() => (tab = "segments")}>Segments</button
        >
        <button
          role="tab"
          aria-selected={tab === "triage"}
          class:active={tab === "triage"}
          onclick={() => (tab = "triage")}>Triage</button
        >
      </div>
    {/if}

    {#if tab === "segments"}
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Address range</th>
            <th>Length</th>
            <th>{offsetLabel}</th>
          </tr>
        </thead>
        <tbody>
          {#if !cap}
            <tr class="none">
              <td colspan="4">
                {path ? "Capture could not be read — see the error below." : "Open a memory capture to inspect its segments."}
              </td>
            </tr>
          {/if}
          {#each segments as s (s.index)}
            <tr class:selected={sel === s.index} class="click" onclick={() => (sel = s.index)}>
              <td>{s.index}</td>
              <td class="mono">
                {cap?.hasMap ? `${fmtAddr(s.addrStart)} – ${fmtAddr(s.addrEnd - 1)}` : "—"}
              </td>
              <td>{fmtSize(s.length)}</td>
              <td class="mono">{fmtOffset(s.offset)}</td>
            </tr>
          {/each}
        </tbody>
      </table>

      <div class="actions">
        <button onclick={openSelected} disabled={busy || !selected}>Open segment as hex</button>
        <button class="primary" onclick={openWhole} disabled={busy || !cap}>
          Open capture as hex
        </button>
      </div>
    {/if}

    {#if tab === "triage" && cap}
      <div class="triage">
        {#if cap.bugCheck && cap.bugCheck.code}
          <p class="banner">
            <strong>Bugcheck 0x{cap.bugCheck.code.toString(16).toUpperCase().padStart(8, "0")}</strong>
            {#if cap.bugCheck.desc}{cap.bugCheck.desc}{/if}
            <span class="mono dim">
              params: {cap.bugCheck.params.map((p) => `0x${p.toString(16)}`).join(" ")}
            </span>
          </p>
        {/if}
        {#if details?.exception}
          <p class="banner exc">
            <strong>Thread {details.exception.threadId}</strong>
            {details.exception.desc || `Exception 0x${details.exception.code.toString(16)}`}
            at <span class="mono">{fmtAddr(details.exception.address)}</span>
            <span class="mono dim">
              params: {details.exception.params.map((p) => `0x${p.toString(16)}`).join(" ")}
            </span>
          </p>
        {/if}
        {#if cap.hiber}
          <p class="banner">
            Hibernation file — {cap.hiber.pages} page{cap.hiber.pages === 1 ? "" : "s"} ×{" "}
            {fmtSize(cap.hiber.pageSize)}
            {#if cap.hiber.versions?.length}({cap.hiber.versions.join(", ")}){/if}
            <span class="dim">— compressed page bodies are not decompressed</span>
          </p>
        {/if}
        {#if details}
          <p class="meta">
            {#if details.os}<span class="badge">{details.os}</span>{/if}
            {#if details.arch}<span class="badge">{details.arch}</span>{/if}
            {#if details.process}<span class="dim">process: <strong>{details.process}</strong></span>{/if}
            <span class="spacer"></span>
            <button onclick={() => void compareWith()} disabled={busy}>Compare modules with…</button>
          </p>
        {/if}

        {#if details?.threads?.length}
          <h3>Threads ({details.threads.length})</h3>
          <table>
            <thead>
              <tr>
                <th>TID</th>
                <th>Stack</th>
                <th>IP</th>
                <th>FP</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each details.threads as t (t.id)}
                <tr class:selected={stackThread === t.id}>
                  <td>{t.id}</td>
                  <td class="mono">
                    {t.stackStart ? `${fmtAddr(t.stackStart)}–${fmtAddr(t.stackEnd ?? 0)}` : "—"}
                  </td>
                  <td class="mono">{regLabel(t, "rip", "eip")}</td>
                  <td class="mono">{regLabel(t, "rbp", "ebp")}</td>
                  <td>
                    <button class="mini" onclick={() => void walkStack(t.id)} disabled={busy}>
                      Walk stack
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if frames.length}
            <h3>
              Stack — thread {stackThread}
              <span class="dim">(frame-pointer walk, raw addresses)</span>
            </h3>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Address</th>
                  <th>Module</th>
                  <th>Offset</th>
                </tr>
              </thead>
              <tbody>
                {#each frames as f, i (i)}
                  <tr>
                    <td>{i}</td>
                    <td class="mono">{fmtAddr(f.addr)}</td>
                    <td>{f.module || "—"}</td>
                    <td class="mono">{f.module ? `+0x${(f.offset ?? 0).toString(16)}` : "—"}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        {/if}

        {#if details?.modules?.length}
          <h3>Modules ({details.modules.length})</h3>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Base</th>
                <th>Size</th>
                <th>Path</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each details.modules as m, i (i)}
                <tr>
                  <td>{m.name || "—"}</td>
                  <td class="mono">{fmtAddr(m.base)}</td>
                  <td class="mono">{fmtSize(m.size)}</td>
                  <td class="dim path-cell">{m.path || ""}</td>
                  <td>
                    <button
                      class="mini"
                      onclick={() => void extractRegion(m.base, m.size || 1)}
                      disabled={busy || !m.size}>Extract</button
                    >
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}

        {#if diff}
          <h3>
            Module diff vs <span class="mono path">{diffPath}</span> — {diff.common} common
          </h3>
          <div class="diff-cols">
            <div>
              <h4>Only in this dump ({(diff.onlyA ?? []).length})</h4>
              <ul class="mono">
                {#each diff.onlyA ?? [] as m (m.base)}
                  <li>{fmtAddr(m.base)} {m.name}</li>
                {/each}
              </ul>
            </div>
            <div>
              <h4>Only in other ({(diff.onlyB ?? []).length})</h4>
              <ul class="mono">
                {#each diff.onlyB ?? [] as m (m.base)}
                  <li>{fmtAddr(m.base)} {m.name}</li>
                {/each}
              </ul>
            </div>
          </div>
        {/if}

        {#if cap.hasMap}
          <h3>Extract region</h3>
          <div class="options">
            <label class="field">
              <span>Address</span>
              <input class="mono" placeholder="0x1000" bind:value={extractAddr} />
            </label>
            <label class="field">
              <span>Length</span>
              <input class="mono" placeholder="4096" bind:value={extractLen} />
            </label>
            <button onclick={extractFromFields} disabled={busy}>Extract to file…</button>
          </div>
        {/if}
      </div>
    {/if}

    {#if error}<p class="error">{error}</p>{/if}
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
    width: min(860px, 94vw);
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
    margin-bottom: 10px;
  }

  h2 {
    margin: 0;
    font-size: 18px;
    letter-spacing: 0.02em;
  }

  .meta {
    margin: 0 0 12px;
    font-size: 12.5px;
    color: var(--text-dim);
  }

  .path {
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    max-width: 62ch;
    vertical-align: bottom;
  }

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
  }

  .badge {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.06em;
    padding: 2px 8px;
    border: 1px solid var(--accent);
    border-radius: 999px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .options {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 10px;
    font-size: 12.5px;
  }

  .field {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }

  .field input {
    width: 14ch;
    padding: 4px 6px;
    font-size: 12.5px;
    background: var(--bg-input, transparent);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
  }

  .spacer {
    flex: 1;
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

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 12px;
  }

  .error {
    margin: 10px 0 0;
    font-size: 12px;
    color: #e07b7b;
  }

  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 10px;
  }

  .tabs button {
    padding: 4px 12px;
    font-size: 12px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-dim);
    border-radius: 6px;
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--text);
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .triage h3 {
    margin: 14px 0 6px;
    font-size: 13px;
  }

  .triage h4 {
    margin: 0 0 4px;
    font-size: 12px;
    color: var(--text-dim);
  }

  .banner {
    margin: 0 0 8px;
    padding: 6px 10px;
    font-size: 12.5px;
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 4px;
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }

  .banner.exc {
    border-left-color: #e07b7b;
    background: color-mix(in srgb, #e07b7b 10%, transparent);
  }

  button.mini {
    padding: 2px 8px;
    font-size: 11px;
  }

  .path-cell {
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .diff-cols {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .diff-cols ul {
    margin: 0;
    padding: 6px 10px;
    list-style: none;
    font-size: 11.5px;
    border: 1px solid var(--border);
    border-radius: 5px;
    max-height: 160px;
    overflow: auto;
  }

  .diff-cols li {
    padding: 1px 0;
  }
</style>
