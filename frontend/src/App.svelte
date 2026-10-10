<script lang="ts">
  import { onMount } from "svelte";
  import { store } from "./lib/state.svelte";
  import { Events, svc } from "./lib/api";
  import * as A from "./lib/actions";
  import { findAction } from "./lib/keymap";
  import { disclaimerAccepted, acceptDisclaimer } from "./lib/disclaimer";
  import Toolbar from "./lib/Toolbar.svelte";
  import TabBar from "./lib/TabBar.svelte";
  import StatusBar from "./lib/StatusBar.svelte";
  import FindPanel from "./lib/FindPanel.svelte";
  import HexView from "./lib/hex/HexView.svelte";
  import Disclaimer from "./lib/dialogs/Disclaimer.svelte";
  import About from "./lib/dialogs/About.svelte";
  import Preferences from "./lib/dialogs/Preferences.svelte";
  import Disk from "./lib/dialogs/Disk.svelte";
  import Carve from "./lib/dialogs/Carve.svelte";
  import Ethics from "./lib/dialogs/Ethics.svelte";
  import Browser from "./lib/dialogs/Browser.svelte";
  import Memory from "./lib/dialogs/Memory.svelte";
  import Case from "./lib/dialogs/Case.svelte";
  import Script from "./lib/dialogs/Script.svelte";
  import Template from "./lib/dialogs/Template.svelte";
  import Dump from "./lib/dialogs/Dump.svelte";
  import Compare from "./lib/dialogs/Compare.svelte";
  import Utilities from "./lib/dialogs/Utilities.svelte";

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
      if (
        store.showPrefs ||
        store.showAbout ||
        store.showDisk ||
        store.showCarve ||
        store.showBrowser ||
        store.showMemory ||
        store.showCase ||
        store.showScript ||
        store.showTemplate ||
        store.showDump ||
        store.showCompare ||
        store.showUtilities
      ) {
        store.showPrefs = false;
        store.showAbout = false;
        store.showDisk = false;
        store.showCarve = false;
        store.showBrowser = false;
        store.showMemory = false;
        store.showCase = false;
        store.showScript = false;
        store.showTemplate = false;
        store.showDump = false;
        store.showCompare = false;
        store.showUtilities = false;
        return;
      }
      if (store.showEthics) {
        store.showEthics = false;
        return;
      }
      if (store.findOpen) store.findOpen = false;
      return;
    }
    const inInput = isTypingTarget(e);
    const action = findAction(store.prefs?.shortcuts, e);
    if (!action) return;

    switch (action) {
      case "file.open":
        e.preventDefault();
        void A.openFile();
        break;
      case "file.new":
        e.preventDefault();
        void A.newDocument();
        break;
      case "file.save":
        e.preventDefault();
        void A.saveActive();
        break;
      case "file.saveAs":
        e.preventDefault();
        void A.saveActiveAs();
        break;
      case "edit.undo":
        if (inInput) return;
        e.preventDefault();
        void A.undo();
        break;
      case "edit.redo":
        if (inInput) return;
        e.preventDefault();
        void A.redo();
        break;
      case "edit.selectAll":
        if (inInput) return;
        if (!doc) return;
        e.preventDefault();
        void A.selectAll();
        break;
      case "edit.copy":
        if (inInput || !doc) return;
        e.preventDefault();
        void store.copyFn?.("hex");
        break;
      case "edit.copyText":
        if (inInput || !doc) return;
        e.preventDefault();
        void store.copyFn?.("text");
        break;
      case "search.find":
        e.preventDefault();
        store.findOpen = true;
        break;
      case "goto.offset":
        e.preventDefault();
        document.querySelector<HTMLButtonElement>(".offset-btn")?.click();
        break;
      case "preferences.open":
        e.preventDefault();
        store.showPrefs = true;
        break;
      default:
        // Reserved actions (search.replace, search.next/prev, view.theme,
        // help.*) have no UI surface yet; the binding is kept for them.
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
  {#if store.showDisk}
    <Disk />
  {/if}
  {#if store.showCarve}
    <Carve />
  {/if}
  {#if store.showEthics}
    <Ethics
      onaccept={(mod) => {
        if (mod === "memory") store.showMemory = true;
        else store.showBrowser = true;
      }}
    />
  {/if}
  {#if store.showBrowser}
    <Browser />
  {/if}
  {#if store.showMemory}
    <Memory />
  {/if}
  {#if store.showCase}
    <Case />
  {/if}
  {#if store.showScript}
    <Script />
  {/if}
  {#if store.showTemplate}
    <Template />
  {/if}
  {#if store.showDump}
    <Dump />
  {/if}
  {#if store.showCompare}
    <Compare />
  {/if}
  {#if store.showUtilities}
    <Utilities />
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
