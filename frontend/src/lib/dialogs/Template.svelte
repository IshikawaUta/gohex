<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type {
    TemplateInfo,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";
  import type {
    Value,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/template/models";

  let path = $state("");
  let info = $state<TemplateInfo | null>(null);
  let offsetText = $state("0");
  let values = $state<Value[] | null>(null);
  let busy = $state(false);
  let error = $state("");

  let doc = $derived(store.active);

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open template",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
        Filters: [{ DisplayName: "Templates", Pattern: "*.tpl" }],
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (!target) return;
      path = target;
      values = null;
      error = "";
      busy = true;
      try {
        info = await svc.TemplateLoad(path);
        flash(`Template “${info.name}” — ${info.fields?.length ?? 0} fields`);
      } catch (e) {
        info = null;
        error = errMsg(e);
      } finally {
        busy = false;
      }
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  function parseOffset(): number {
    const text = offsetText.trim();
    if (!text) throw new Error("Enter an offset, e.g. 0x200");
    const base = /^0[xX]/.test(text) ? 16 : 10;
    const n = parseInt(base === 16 ? text.slice(2) : text, base);
    if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
      throw new Error(`"${offsetText}" is not a valid offset`);
    }
    return n;
  }

  async function apply(): Promise<void> {
    if (!path || !doc) return;
    busy = true;
    error = "";
    try {
      const off = parseOffset();
      values = await svc.TemplateApply(path, doc.id, off);
      flash(`Template applied at 0x${off.toString(16)} — ${values?.length ?? 0} fields`);
    } catch (e) {
      values = null;
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function useCursor(): void {
    offsetText = `0x${store.cursor.toString(16).toUpperCase()}`;
  }

  function fmtOffset(n: number): string {
    return `0x${n.toString(16).toUpperCase().padStart(8, "0")}`;
  }

  function fmtSize(n: number): string {
    return `${n} B`;
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Template overlay"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showTemplate = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showTemplate = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Template</h2>
      <button class="primary" onclick={() => void apply()} disabled={busy || !path || !doc}>
        {busy ? "Working…" : "Apply"}
      </button>
    </div>

    <p class="meta">
      Overlays a WinHex-style structure template on the active document at a
      chosen offset — typed fields, arrays, GUIDs, FILETIME — read-only.
    </p>

    <div class="options">
      <button onclick={() => void choose()} disabled={busy}>Open template…</button>
      {#if path}
        <span class="mono path">{path}</span>
      {/if}
      {#if info}
        <span class="badge">{info.name}</span>
        <span class="dim">{info.fields?.length ?? 0} fields · {fmtSize(info.size)}{info.bigEndian ? " · big-endian" : ""}</span>
      {/if}
      <span class="spacer"></span>
      {#if doc}
        <label class="field">
          <span>Offset</span>
          <input
            class="mono"
            placeholder="0x200"
            bind:value={offsetText}
            onkeydown={(e) => {
              if (e.key === "Enter") void apply();
            }}
          />
        </label>
        <button onclick={useCursor} title="Use the current cursor offset">Cursor</button>
      {/if}
    </div>

    {#if !doc}
      <p class="dim">Open a document to apply the template to.</p>
    {/if}

    {#if info}
      <table>
        <thead>
          <tr>
            <th>Offset</th>
            <th>Type</th>
            <th>Name</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {#each info.fields as f}
            <tr>
              <td class="mono">{fmtOffset(f.offset)}</td>
              <td class="mono">{f.type}{f.count > 1 ? `[${f.count}]` : ""}</td>
              <td>{f.name}</td>
              <td class="dim">{f.description ?? ""}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if values}
      <table class="result">
        <thead>
          <tr>
            <th>Offset</th>
            <th>Name</th>
            <th>Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {#each values as v}
            <tr>
              <td class="mono">{fmtOffset(v.offset)}</td>
              <td>{v.name}</td>
              <td class="mono">{v.type}</td>
              <td class="mono">{v.display}</td>
            </tr>
          {/each}
        </tbody>
      </table>
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

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
  }

  .path {
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    max-width: 42ch;
    vertical-align: bottom;
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
    margin-bottom: 12px;
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
    width: 12ch;
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
    margin-bottom: 12px;
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
  }

  table.result td {
    word-break: break-all;
    white-space: normal;
  }

  .error {
    margin: 10px 0 0;
    font-size: 12px;
    color: #e07b7b;
  }
</style>
