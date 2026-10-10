<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { fmtOffsetHex } from "../format";
  import * as NM from "../macros";
  import * as A from "../actions";

  let name = $state("");
  let ops = $state<NM.MacroOp[]>([]);
  let saved = $state<NM.Macro[]>([]);
  let error = $state("");
  let recording = $derived(NM.isRecording());

  $effect(() => {
    if (store.showMacro) {
      saved = NM.list();
      ops = NM.recordedOps();
      error = "";
    }
  });

  function refresh(): void {
    saved = NM.list();
    ops = NM.recordedOps();
  }

  function start(): void {
    NM.startRecording();
    ops = [];
    flash("Macro recording started — navigation, find, copy, and bookmarks are captured");
  }

  function stop(): void {
    ops = NM.stopRecording();
    flash(`Macro recording stopped (${ops.length} ops)`);
  }

  function save(): void {
    if (!NM.saveMacro(name, ops)) {
      error = "Give the macro a name and record at least one op.";
      return;
    }
    error = "";
    flash(`Saved macro "${name.trim()}"`);
    name = "";
    refresh();
  }

  function load(m: NM.Macro): void {
    name = m.name;
    ops = [...m.ops];
    error = "";
  }

  function remove(m: NM.Macro): void {
    NM.removeMacro(m.name);
    refresh();
  }

  async function replay(m: NM.Macro): Promise<void> {
    store.showMacro = false;
    await A.replayMacro(m);
  }

  async function replayEdited(): Promise<void> {
    if (ops.length === 0 || !name.trim()) {
      error = "Nothing to replay — save or name the op list first.";
      return;
    }
    store.showMacro = false;
    await A.replayMacro({ name: name.trim(), ops: [...ops], created: new Date().toISOString() });
  }

  async function exportMacro(m: NM.Macro): Promise<void> {
    try {
      await navigator.clipboard.writeText(NM.exportJSON(m));
      flash(`Macro "${m.name}" JSON copied to clipboard`);
    } catch {
      error = "Clipboard write failed — select and copy from the ops list instead.";
    }
  }

  async function importMacro(): Promise<void> {
    let text = "";
    try {
      text = await navigator.clipboard.readText();
    } catch {
      error = "Clipboard is empty or unreadable — copy the macro JSON first.";
      return;
    }
    const m = NM.importJSON(text);
    if (!m) {
      error = "Clipboard does not contain a valid gohex-macro-v1 export.";
      return;
    }
    NM.saveMacro(m.name, m.ops);
    error = "";
    flash(`Imported macro "${m.name}"`);
    refresh();
  }

  function describe(op: NM.MacroOp): string {
    switch (op.kind) {
      case "goto":
        return `goto ${op.expr}`;
      case "find":
        return `find (${op.mode}${op.forward ? "" : ", prev"}) ${JSON.stringify(op.expr)}`;
      case "copy":
        return `copy ${op.what}`;
      case "bookmark":
        return "bookmark cursor";
      case "selectAll":
        return "select all";
      case "wait":
        return `wait ${op.ms} ms`;
    }
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Macros"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showMacro = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showMacro = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Macros</h2>
      <button class="ghost" onclick={() => (store.showMacro = false)}>Close</button>
    </div>
    <p class="meta">
      Record navigation, find, copy, and bookmark actions, then replay them
      against the active document. Macros are examiner automation: they do
      not write to evidence, and a failing step stops the run so nothing is
      misreported.
    </p>

    <div class="bar">
      {#if !recording}
        <button class="primary" onclick={start}>● Record</button>
      {:else}
        <button class="danger" onclick={stop}>■ Stop ({ops.length} ops)</button>
      {/if}
      <input bind:value={name} placeholder="Macro name" />
      <button onclick={save} disabled={recording || ops.length === 0}>Save</button>
      <button onclick={() => void replayEdited()} disabled={recording || ops.length === 0}>
        Replay edited
      </button>
      <button onclick={() => void importMacro()} disabled={recording}>Import JSON</button>
    </div>

    {#if ops.length}
      <div class="ops">
        <h3>Captured ops</h3>
        <ol>
          {#each ops as op, i (i)}
            <li>{describe(op)}</li>
          {/each}
        </ol>
      </div>
    {/if}

    {#if saved.length}
      <h3>Saved macros</h3>
      <table>
        <thead>
          <tr><th>Name</th><th>Ops</th><th>Created</th><th></th></tr>
        </thead>
        <tbody>
          {#each saved as m (m.name)}
            <tr>
              <td>{m.name}</td>
              <td class="dim">{m.ops.length}</td>
              <td class="dim">{new Date(m.created).toLocaleString()}</td>
              <td class="ops-cell">
                <button class="mini" onclick={() => load(m)}>Load</button>
                <button class="mini" onclick={() => void replay(m)}>Replay</button>
                <button class="mini" onclick={() => void exportMacro(m)}>Copy JSON</button>
                <button class="mini" onclick={() => remove(m)}>✕</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="dim">No saved macros yet.</p>
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
    width: min(680px, 96vw);
    max-height: 80vh;
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
    margin-bottom: 8px;
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  h3 {
    margin: 12px 0 6px;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-dim);
  }
  .meta {
    margin: 0 0 10px;
    font-size: 12.5px;
    color: var(--text-dim);
  }
  .bar {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }
  .bar input {
    flex: 1;
    min-width: 140px;
    font-size: 12.5px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-input, transparent);
    color: var(--text);
  }
  .ops {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    max-height: 160px;
    overflow: auto;
    margin-bottom: 8px;
  }
  .ops ol {
    margin: 0;
    padding-left: 18px;
    font-family: var(--font-mono);
    font-size: 12px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th,
  td {
    text-align: left;
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
  }
  .dim {
    color: var(--text-dim);
  }
  .ops-cell {
    white-space: nowrap;
  }
  .mini {
    border: 1px solid var(--border);
    background: transparent;
    color: var(--text-dim);
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 4px;
    cursor: pointer;
    margin-right: 4px;
  }
  .ghost,
  .danger {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
  }
  .danger {
    border-color: var(--danger, #e5534b);
    color: var(--danger, #e5534b);
  }
  .error {
    color: var(--danger, #e5534b);
    margin-top: 8px;
    font-size: 12.5px;
  }
</style>
