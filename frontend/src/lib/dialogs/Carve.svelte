<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import * as A from "../actions";
  import type { Carved, SpecInfo } from "../../../bindings/github.com/IshikawaUta/gohex/internal/recovery/models";
  import type { SaveResult } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";

  let path = $state("");
  let specs = $state<SpecInfo[]>([]);
  let chosen = $state<Record<string, boolean>>({});
  let fromText = $state("");
  let toText = $state("");
  let allowTruncated = $state(false);
  let results = $state<Carved[]>([]);
  let sel = $state(-1);
  let busy = $state(false);
  let error = $state("");

  let types = $derived(
    Object.entries(chosen)
      .filter(([, on]) => on)
      .map(([name]) => name),
  );
  let selected = $derived(sel >= 0 && sel < results.length ? results[sel] : null);
  let allOn = $derived(specs.length > 0 && types.length === specs.length);

  $effect(() => {
    if (!store.showCarve || specs.length > 0) return;
    void svc
      .CarveTypes()
      .then((list) => {
        specs = list ?? [];
        const init: Record<string, boolean> = {};
        for (const s of specs) init[s.name] = true;
        chosen = init;
      })
      .catch((e) => {
        error = errMsg(e);
      });
  });

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open disk image",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (!target) return;
      path = target;
      results = [];
      sel = -1;
      error = "";
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  function parseNum(raw: string): number {
    const text = raw.trim();
    if (!text) return 0;
    const base = /^0[xX]/.test(text) ? 16 : 10;
    const n = parseInt(base === 16 ? text.slice(2) : text, base);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error(`"${raw}" is not a valid number`);
    }
    return n;
  }

  async function scan(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    results = [];
    sel = -1;
    try {
      const from = parseNum(fromText);
      const to = parseNum(toText);
      results =
        (await svc.CarveScan(path, from, to, types.length ? types : null, 0, allowTruncated)) ?? [];
      flash(
        results.length
          ? `${results.length} object${results.length === 1 ? "" : "s"} recovered`
          : "No matching files found",
      );
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportSelected(): Promise<void> {
    if (!path || !selected) return;
    const name = `${String(selected.index).padStart(4, "0")}${selected.ext}`;
    let dst: string;
    try {
      dst = (await Dialogs.SaveFile({ Title: "Export recovered file", Filename: name })) as string;
    } catch (e) {
      error = `Export dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const res: SaveResult = await svc.CarveExport(path, selected, dst);
      flash(`Recovered ${res.bytesSaved} bytes → ${res.path} (sha256:${res.sha256})`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function openAsHex(): Promise<void> {
    if (!path || !selected) return;
    busy = true;
    error = "";
    try {
      const doc = await svc.OpenRange(path, selected.offset, selected.length);
      store.activeId = doc.id;
      await A.refreshDocs();
      A.syncSelectionFromDoc();
      store.showCarve = false;
      flash(`${doc.name} — ${doc.size} bytes`);
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
  aria-label="File carving"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showCarve = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showCarve = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Carve</h2>
      <button class="primary" onclick={choose}>Open image…</button>
    </div>

    {#if path}
      <p class="meta"><span class="mono path">{path}</span></p>
    {/if}

    <div class="options">
      <label class="field">
        <span>From</span>
        <input class="mono" placeholder="0" bind:value={fromText} />
      </label>
      <label class="field">
        <span>To</span>
        <input class="mono" placeholder="end" bind:value={toText} />
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={allowTruncated} />
        Include truncated candidates
      </label>
      <span class="spacer"></span>
      <button
        onclick={() => {
          const next = !allOn;
          const init: Record<string, boolean> = {};
          for (const s of specs) init[s.name] = next;
          chosen = init;
        }}
      >
        {allOn ? "Clear all types" : "Select all types"}
      </button>
      <button class="primary" onclick={() => void scan()} disabled={busy || !path}>
        {busy ? "Scanning…" : "Scan"}
      </button>
    </div>

    <ul class="chips">
      {#each specs as s (s.name)}
        <li>
          <label class="chip" class:on={chosen[s.name]}>
            <input type="checkbox" bind:checked={chosen[s.name]} />
            {s.display}
            <span class="dim">{s.extent === "footer" ? "⌁" : "⌘"}</span>
          </label>
        </li>
      {/each}
    </ul>

    <table>
      <thead>
        <tr><th>#</th><th>Type</th><th>Offset</th><th>Size</th><th>Header</th><th></th></tr>
      </thead>
      <tbody>
        {#if results.length === 0}
          <tr class="none">
            <td colspan="6">{path ? "Nothing recovered yet — run a scan." : "Open an image to carve."}</td>
          </tr>
        {/if}
        {#each results as r (r.index)}
          <tr
            class:selected={sel === r.index}
            class="click"
            onclick={() => (sel = r.index)}
          >
            <td>{r.index}</td>
            <td>
              {r.display}
              {#if r.truncated}<span class="warn">truncated</span>{/if}
            </td>
            <td class="mono">{fmtOffset(r.offset)}</td>
            <td>{fmtSize(r.length)}</td>
            <td class="mono">{r.headerLen} B</td>
            <td class="mono dim">{fmtOffset(r.offset + r.length)}</td>
          </tr>
        {/each}
      </tbody>
    </table>

    <div class="actions">
      <button onclick={exportSelected} disabled={busy || !selected}>Export…</button>
      <button class="primary" onclick={openAsHex} disabled={busy || !selected}>
        Open as hex
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

  .options {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }

  .field {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }

  .field input {
    width: 12ch;
    padding: 4px 6px;
    font-size: 12.5px;
    background: var(--bg-input, transparent);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
  }

  .check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12.5px;
  }

  .spacer {
    flex: 1;
  }

  .chips {
    list-style: none;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0 0 12px;
    padding: 0;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: 999px;
    cursor: pointer;
    color: var(--text-dim);
  }

  .chip input {
    display: none;
  }

  .chip.on {
    color: var(--text);
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 18%, transparent);
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
    margin-left: 6px;
    font-size: 10.5px;
    color: #d8a657;
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
