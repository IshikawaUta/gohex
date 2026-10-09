<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import * as A from "../actions";
  import type {
    Capture,
    Location,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/memory/models";

  let path = $state("");
  let cap = $state<Capture | null>(null);
  let sel = $state(-1);
  let physText = $state("");
  let located = $state<Location | null>(null);
  let busy = $state(false);
  let error = $state("");

  let segments = $derived(cap?.segments ?? []);
  let selected = $derived(sel >= 0 && sel < segments.length ? segments[sel] : null);

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

  function parseNum(raw: string): number {
    const text = raw.trim();
    if (!text) throw new Error("Enter a physical address, e.g. 0x1000");
    const base = /^0[xX]/.test(text) ? 16 : 10;
    const n = parseInt(base === 16 ? text.slice(2) : text, base);
    if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
      throw new Error(`"${raw}" is not a valid address`);
    }
    return n;
  }

  async function locate(): Promise<void> {
    if (!path || !cap?.hasPhys) return;
    busy = true;
    error = "";
    try {
      const phys = parseNum(physText);
      located = await svc.MemoryLocate(path, phys);
      sel = located.segment;
      flash(`${fmtPhys(phys)} → file offset ${fmtOffset(located.offset)}`);
    } catch (e) {
      located = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function openRange(offset: number, size: number): Promise<void> {
    if (!path || size <= 0) return;
    busy = true;
    error = "";
    try {
      const doc = await svc.OpenRange(path, offset, size);
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
    void openRange(0, cap.size);
  }

  function openSelected(): void {
    if (!selected) return;
    void openRange(selected.offset, selected.length);
  }

  function openLocated(): void {
    if (!located) return;
    const seg = segments[located.segment];
    if (!seg) return;
    void openRange(located.offset, seg.offset + seg.length - located.offset);
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

  function fmtPhys(n: number): string {
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
          {cap.hasPhys ? "physical address map" : "no address map — headerless dump"}
        </span>
        <span class="spacer"></span>
        {#if cap.hasPhys}
          <label class="field">
            <span>Physical address</span>
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

    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Physical range</th>
          <th>Length</th>
          <th>File offset</th>
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
              {cap?.hasPhys ? `${fmtPhys(s.physStart)} – ${fmtPhys(s.physEnd - 1)}` : "—"}
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
</style>
