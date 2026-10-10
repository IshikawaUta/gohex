<script lang="ts">
  import { store } from "./state.svelte";
  import * as A from "./actions";
  import type { Preferences } from "../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

  const encodings = ["ASCII", "UTF-8", "UTF-16LE", "UTF-16BE", "EBCDIC"];
  const themes = ["dark", "light", "high-contrast"];
  const hashAlgos = ["sha256", "sha512", "sha1", "md5", "crc32", "crc32c", "blake3", "xxhash64"];

  let doc = $derived(store.active);

  async function onHash(ev: Event): Promise<void> {
    const sel = (ev.target as HTMLSelectElement).value;
    (ev.target as HTMLSelectElement).value = "";
    if (!sel) return;
    const [algo, scope] = sel.split("|");
    await A.hashActive(algo, scope === "sel");
  }

  async function onTheme(ev: Event): Promise<void> {
    const theme = (ev.target as HTMLSelectElement).value;
    if (!store.prefs) return;
    await A.preferencesChanged({ ...store.prefs, theme } as Preferences);
  }
</script>

<div class="toolbar">
  <button class="tb" onclick={() => A.openFile()} title="{store.t('menu.file.open')} (Ctrl+O)">
    {store.t("menu.file.open")}
  </button>
  <button class="tb" onclick={() => A.newDocument()} title="New document (Ctrl+N)">
    New
  </button>
  <button
    class="tb"
    onclick={() => A.saveActive()}
    disabled={!doc}
    title="{store.t('menu.file.save')} (Ctrl+S)"
  >
    {store.t("menu.file.save")}
  </button>
  <button class="tb" onclick={() => A.saveActiveAs()} disabled={!doc} title="Save As (Ctrl+Shift+S)">
    {store.t("menu.file.saveAs")}
  </button>
  <span class="sep"></span>
  <button class="tb" onclick={() => (store.showDisk = true)} title="Disk image browser">
    Disk
  </button>
  <button class="tb" onclick={() => (store.showCarve = true)} title="Carve files out of an image">
    Carve
  </button>
  <button class="tb" onclick={() => A.openBrowser()} title="Browser history, downloads, bookmarks">
    Browser
  </button>
  <button class="tb" onclick={() => A.openMemory()} title="Memory capture & crash dump viewer (read-only)">
    Memory
  </button>
  <button class="tb" onclick={() => (store.showCase = true)} title="Forensic case, evidence and report">
    Case
  </button>
  <button
    class="tb"
    onclick={() => (store.showScript = true)}
    title="Run a sandboxed automation script over the open documents"
  >
    Script
  </button>
  <button
    class="tb"
    onclick={() => (store.showTemplate = true)}
    title="Overlay a structure template on the active document (read-only)"
  >
    Template
  </button>
  <button
    class="tb"
    onclick={() => (store.showDump = true)}
    title="Parse a crash report: macOS/iOS .ips, Android tombstone, Windows WER (read-only)"
  >
    Crash report
  </button>
  <button
    class="tb"
    onclick={() => (store.showCompare = true)}
    title="Byte-compare two open documents and list the differing ranges (read-only)"
  >
    Compare
  </button>
  <span class="sep"></span>
  <button
    class="tb"
    onclick={() => A.undo()}
    disabled={!doc?.canUndo}
    title="{store.t('menu.edit.undo')} — {doc?.undoLabel ?? ''} (Ctrl+Z)"
  >
    ↶ {store.t("menu.edit.undo")}
  </button>
  <button
    class="tb"
    onclick={() => A.redo()}
    disabled={!doc?.canRedo}
    title="{store.t('menu.edit.redo')} — {doc?.redoLabel ?? ''} (Ctrl+Y)"
  >
    ↷ {store.t("menu.edit.redo")}
  </button>
  <span class="sep"></span>
  <button
    class="tb"
    class:active={store.findOpen}
    onclick={() => (store.findOpen = !store.findOpen)}
    disabled={!doc}
    title="{store.t('menu.search.find')} (Ctrl+F)"
  >
    {store.t("menu.search.find")}
  </button>

  <span class="spacer"></span>

  <label class="lbl" for="enc-select">{store.t("menu.view.encoding")}</label>
  <select
    id="enc-select"
    class="sel"
    value={doc?.encoding ?? "ASCII"}
    disabled={!doc}
    onchange={(e) => A.setEncoding((e.target as HTMLSelectElement).value)}
  >
    {#each encodings as enc}
      <option value={enc}>{enc}</option>
    {/each}
  </select>

  <label class="lbl" for="theme-select">{store.t("menu.view.theme")}</label>
  <select id="theme-select" class="sel" value={store.theme} onchange={onTheme}>
    {#each themes as th}
      <option value={th}>{th}</option>
    {/each}
  </select>

  <select class="sel" value="" disabled={!doc} onchange={onHash} title="Compute checksum">
    <option value="" disabled>Hash…</option>
    <optgroup label="File">
      {#each hashAlgos as a}
        <option value={a}>{a.toUpperCase()}</option>
      {/each}
    </optgroup>
    <optgroup label="Selection">
      {#each ["sha256", "md5", "sha1"] as a}
        <option value="{a}|sel">{a.toUpperCase()} (selection)</option>
      {/each}
    </optgroup>
  </select>

  <button class="tb" onclick={() => (store.showPrefs = true)} title="Preferences (Ctrl+,)">
    ⚙
  </button>
  <button class="tb" onclick={() => (store.showAbout = true)} title="About">
    ?
  </button>
</div>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 6px;
    height: var(--toolbar-h);
    padding: 0 8px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    flex: none;
  }

  .tb {
    padding: 4px 9px;
    font-size: 12px;
    white-space: nowrap;
  }

  .tb.active {
    background: var(--accent-soft);
    border-color: var(--accent);
  }

  .sep {
    width: 1px;
    height: 18px;
    background: var(--border);
    margin: 0 3px;
  }

  .lbl {
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .sel {
    padding: 3px 6px;
    font-size: 12px;
    max-width: 160px;
  }
</style>
