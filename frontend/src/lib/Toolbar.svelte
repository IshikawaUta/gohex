<script lang="ts">
  import { store } from "./state.svelte";
  import * as A from "./actions";
  import type { Preferences } from "../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

  const encodings = ["ASCII", "UTF-8", "UTF-16LE", "UTF-16BE", "EBCDIC"];
  const themes = ["dark", "light", "high-contrast"];
  const hashAlgos = ["sha256", "sha512", "sha1", "md5", "crc32", "crc32c", "blake3", "xxhash64"];

  let doc = $derived(store.active);

  let toolsOpen = $state(false);
  let toolsRoot: HTMLDivElement | undefined = $state(undefined);
  let toolsTrigger: HTMLButtonElement | undefined = $state(undefined);
  let toolsMenu: HTMLDivElement | undefined = $state(undefined);

  const toolItems = [
    { label: "Disk", title: "Disk image browser", run: () => (store.showDisk = true) },
    { label: "Carve", title: "Carve files out of an image", run: () => (store.showCarve = true) },
    { label: "Browser", title: "Browser history, downloads, bookmarks", run: () => A.openBrowser() },
    {
      label: "Memory",
      title: "Memory capture & crash dump viewer (read-only)",
      run: () => A.openMemory(),
    },
    { label: "Case", title: "Forensic case, evidence and report", run: () => (store.showCase = true) },
    {
      label: "Script",
      title: "Run a sandboxed automation script over the open documents",
      run: () => (store.showScript = true),
    },
    {
      label: "Template",
      title: "Overlay a structure template on the active document (read-only)",
      run: () => (store.showTemplate = true),
    },
    {
      label: "Crash report",
      title: "Parse a crash report: macOS/iOS .ips, Android tombstone, Windows WER (read-only)",
      run: () => (store.showDump = true),
    },
    {
      label: "Compare",
      title: "Byte-compare two open documents and list the differing ranges (read-only)",
      run: () => (store.showCompare = true),
    },
    {
      label: "Utilities",
      title: "Entropy, calculator, regex, strings, split/join, shred, generators, timestamps, PNG export",
      run: () => (store.showUtilities = true),
    },
  ];

  $effect(() => {
    if (toolsOpen) {
      queueMicrotask(() => toolsMenu?.querySelector("button")?.focus());
    }
  });

  function toggleTools(): void {
    toolsOpen = !toolsOpen;
  }

  function pickTool(i: number): void {
    toolsOpen = false;
    toolsTrigger?.focus();
    toolItems[i].run();
  }

  function onToolKey(e: KeyboardEvent): void {
    if (e.key === "Escape") {
      e.stopPropagation();
      toolsOpen = false;
      toolsTrigger?.focus();
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const buttons = Array.from(toolsMenu?.querySelectorAll("button") ?? []);
      if (buttons.length === 0) return;
      const idx = buttons.indexOf(document.activeElement as HTMLButtonElement);
      const next =
        e.key === "ArrowDown"
          ? (idx + 1) % buttons.length
          : (idx - 1 + buttons.length) % buttons.length;
      buttons[next]?.focus();
    }
  }

  function onWindowClick(e: MouseEvent): void {
    if (toolsOpen && toolsRoot && !toolsRoot.contains(e.target as Node)) {
      toolsOpen = false;
    }
  }

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

<svelte:window onclick={onWindowClick} />

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
  <div class="tools" bind:this={toolsRoot}>
    <button
      class="tb"
      class:active={toolsOpen}
      bind:this={toolsTrigger}
      aria-haspopup="menu"
      aria-expanded={toolsOpen}
      onclick={toggleTools}
      title="Forensic tools & panels (Disk, Carve, Browser, Memory, Case, Script, Template, Crash report, Compare)"
    >
      Tools <span class="caret" class:up={toolsOpen}>▾</span>
    </button>
    {#if toolsOpen}
      <div
        class="menu"
        role="menu"
        aria-label="Forensic tools"
        tabindex="-1"
        bind:this={toolsMenu}
        onkeydown={onToolKey}
      >
        {#each toolItems as item, i}
          <button
            class="mi"
            role="menuitem"
            title={item.title}
            onclick={() => pickTool(i)}
          >
            {item.label}
          </button>
        {/each}
      </div>
    {/if}
  </div>
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
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    min-height: var(--toolbar-h);
    padding: 4px 8px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    flex: none;
  }

  .tb {
    padding: 4px 9px;
    font-size: 12px;
    white-space: nowrap;
    flex: none;
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
    flex: none;
  }

  .tools {
    position: relative;
    flex: none;
  }

  .caret {
    display: inline-block;
    margin-left: 2px;
    font-size: 9px;
    transition: transform 0.12s ease;
  }

  .caret.up {
    transform: rotate(180deg);
  }

  .menu {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    z-index: 80;
    min-width: 190px;
    padding: 4px;
    display: flex;
    flex-direction: column;
    gap: 1px;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
  }

  .menu:focus {
    outline: none;
  }

  .mi {
    padding: 6px 10px;
    font-size: 12.5px;
    text-align: left;
    white-space: nowrap;
    color: var(--text);
    background: transparent;
    border: none;
    border-radius: 5px;
    cursor: pointer;
  }

  .mi:hover,
  .mi:focus-visible {
    background: var(--accent-soft);
    outline: none;
  }

  .lbl {
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    flex: none;
  }

  .sel {
    padding: 3px 6px;
    font-size: 12px;
    max-width: 160px;
    flex: none;
  }

  @media (max-width: 1150px) {
    .lbl {
      display: none;
    }
  }
</style>
