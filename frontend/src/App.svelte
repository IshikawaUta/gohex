<script lang="ts">
  import { onMount } from "svelte";
  import { store } from "./lib/state.svelte";
  import { Events, svc } from "./lib/api";
  import * as A from "./lib/actions";
  import { disclaimerAccepted, acceptDisclaimer } from "./lib/disclaimer";
  import Toolbar from "./lib/Toolbar.svelte";
  import TabBar from "./lib/TabBar.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import FindPanel from "./lib/FindPanel.svelte";
  import HexView from "./lib/hex/HexView.svelte";
  import Disclaimer from "./lib/dialogs/Disclaimer.svelte";
  import About from "./lib/dialogs/About.svelte";
  import Preferences from "./lib/dialogs/Preferences.svelte";

  let doc = $derived(store.active);
  let ready = $state(false);

  $effect(() => {
    document.title = doc ? `${doc.dirty ? "\u2022 " : ""}${doc.name} \u2014 GoHex` : "GoHex";
  });

  onMount(() => {
    const unsubs: Array<() => void> = [];
    (async () => {
      try {
        document.documentElement.dataset.theme = store.theme;
        await A.loadPrefs();
        await A.applyTheme();
        await A.loadCatalog();
        await A.refreshDocs();
        A.syncSelectionFromDoc();
        const si = await svc.StartupInfo();
        if (si.skipDisclaimer) {
          acceptDisclaimer();
          store.showDisclaimer = false;
        } else {
          store.showDisclaimer = !disclaimerAccepted();
        }
        for (const f of si.files ?? []) {
          await A.openFile(f);
        }
      } catch (e) {
        console.error("init failed", e);
        store.statusMsg = `Init failed: ${e instanceof Error ? e.message : String(e)}`;
      } finally {
        ready = true;
      }

      unsubs.push(Events.On("docs:changed", () => void A.refreshDocs()));
      unsubs.push(Events.On("doc:changed", () => void A.refreshDocs()));
      unsubs.push(Events.On("doc:saved", () => void A.refreshDocs()));
      unsubs.push(
        Events.On("config:changed", async () => {
          await A.loadPrefs();
          await A.applyTheme();
        }),
      );
      unsubs.push(
        Events.On("progress", (ev) => {
          const d = ev.data as { op?: string; done?: number } | null;
          if (d && typeof d.done === "number") {
            store.progress = { op: d.op ?? "…", done: Math.round(d.done) };
            if (d.done >= 100) setTimeout(() => (store.progress = null), 900);
          }
        }),
      );
    })();

    window.addEventListener("keydown", onGlobalKey);
    return () => {
      window.removeEventListener("keydown", onGlobalKey);
      for (const u of unsubs) u();
    };
  });

  function isTypingTarget(e: KeyboardEvent): boolean {
    const t = e.target;
    return (
      t instanceof HTMLInputElement ||
      t instanceof HTMLTextAreaElement ||
      t instanceof HTMLSelectElement
    );
  }

  function onGlobalKey(e: KeyboardEvent): void {
    if (e.key === "Escape") {
      if (store.showPrefs || store.showAbout) {
        store.showPrefs = false;
        store.showAbout = false;
        return;
      }
      if (store.findOpen) store.findOpen = false;
      return;
    }
    const mod = e.ctrlKey || e.metaKey;
    if (!mod) return;
    const key = e.key.toLowerCase();
    const inInput = isTypingTarget(e);

    switch (key) {
      case "o":
        e.preventDefault();
        void A.openFile();
        break;
      case "n":
        e.preventDefault();
        void A.newDocument();
        break;
      case "s":
        e.preventDefault();
        if (e.shiftKey) void A.saveActiveAs();
        else void A.saveActive();
        break;
      case "z":
        if (inInput) return;
        e.preventDefault();
        if (e.shiftKey) void A.redo();
        else void A.undo();
        break;
      case "y":
        if (inInput) return;
        e.preventDefault();
        void A.redo();
        break;
      case "f":
        e.preventDefault();
        store.findOpen = true;
        break;
      case "g":
        e.preventDefault();
        document.querySelector<HTMLButtonElement>(".offset-btn")?.click();
        break;
      case "a":
        if (inInput) return;
        if (!doc) return;
        e.preventDefault();
        void A.selectAll();
        break;
      case "c":
        if (inInput || !doc) return;
        e.preventDefault();
        void store.copyFn?.(e.shiftKey ? "text" : "hex");
        break;
      case ",":
        e.preventDefault();
        store.showPrefs = true;
        break;
      default:
        return;
    }
  }
</script>

<div class="app">
  <Toolbar />
  <TabBar />
  {#if store.findOpen && doc}
    <FindPanel />
  {/if}

  {#if ready}
    {#if doc}
      {#key doc.id}
        <HexView
          docId={doc.id}
          size={doc.size}
          bpl={store.bytesPerLine}
          enc={doc.encoding}
          editable={doc.editingAllowed}
          version={doc.version}
        />
      {/key}
    {:else}
      <div class="welcome">
        <h1>{store.t("wizard.welcome")}</h1>
        <p>{store.t("app.title")}</p>
        <div class="actions">
          <button class="primary big" onclick={() => A.openFile()}>
            {store.t("menu.file.open")} <kbd>Ctrl+O</kbd>
          </button>
          <button class="big" onclick={() => A.newDocument()}>New document</button>
        </div>
        {#if store.prefs?.recentFiles?.length}
          <div class="recent">
            <h3>Recent</h3>
            {#each store.prefs.recentFiles.slice(0, 8) as f (f)}
              <button class="recent-item" onclick={() => A.openFile(f)}>{f}</button>
            {/each}
          </div>
        {/if}
        <p class="note">{store.t("dialog.disclaimer.body")}</p>
      </div>
    {/if}
  {:else}
    <div class="loading">Loading…</div>
  {/if}

  <StatusBar />

  {#if store.showDisclaimer}
    <Disclaimer />
  {/if}
  {#if store.showAbout}
    <About />
  {/if}
  {#if store.showPrefs}
    <Preferences />
  {/if}
</div>

<style>
  .welcome {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 24px;
    overflow: auto;
  }

  .welcome h1 {
    margin: 0;
    font-size: 26px;
  }

  .welcome p {
    margin: 0;
    color: var(--text-dim);
  }

  .actions {
    display: flex;
    gap: 12px;
    margin-top: 12px;
  }

  .big {
    padding: 10px 18px;
    font-size: 14px;
    display: inline-flex;
    gap: 8px;
    align-items: center;
  }

  .recent {
    margin-top: 20px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: min(520px, 90%);
  }

  .recent h3 {
    margin: 0;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-dim);
  }

  .recent-item {
    text-align: left;
    font-family: var(--font-mono);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .note {
    max-width: 640px;
    text-align: center;
    font-size: 11.5px;
    line-height: 1.5;
    margin-top: 18px !important;
  }

  .loading {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-dim);
  }
</style>
