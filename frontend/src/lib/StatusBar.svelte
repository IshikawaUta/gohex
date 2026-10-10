<script lang="ts">
  import { store, flash } from "./state.svelte";
  import { fmtOffsetHex, fmtSize } from "./format";
  import * as A from "./actions";
  import * as BM from "./bookmarks";
  import * as NH from "./navhist";

  let doc = $derived(store.active);
  let editing = $state(false);
  let expr = $state("");

  // navGen tracks history mutations so the buttons re-render.
  let canBack = $derived.by(() => {
    void store.navGen;
    return !!doc && NH.canBack(doc.id);
  });
  let canFwd = $derived.by(() => {
    void store.navGen;
    return !!doc && NH.canForward(doc.id);
  });
  let starred = $derived.by(() => {
    void store.navGen;
    return !!doc && doc.path !== "" && BM.hasBookmark(doc.path, store.cursor);
  });

  function startEdit(): void {
    expr = fmtOffsetHex(store.cursor);
    editing = true;
    requestAnimationFrame(() => {
      inputEl?.focus();
      inputEl?.select();
    });
  }

  let inputEl: HTMLInputElement | undefined = $state();

  async function submit(): Promise<void> {
    editing = false;
    if (expr.trim()) await A.gotoOffset(expr);
  }

  function copyOffset(): void {
    store.copyFn?.("offset");
  }

  function goBack(): void {
    if (!doc) return;
    const off = NH.back(doc.id);
    if (off !== null) {
      store.revealFn?.(off);
      store.navGen++;
    }
  }

  function goForward(): void {
    if (!doc) return;
    const off = NH.forward(doc.id);
    if (off !== null) {
      store.revealFn?.(off);
      store.navGen++;
    }
  }

  function toggleBookmark(): void {
    if (!doc) return;
    if (!doc.path) {
      flash("Save the file first — bookmarks are keyed by path");
      return;
    }
    if (BM.hasBookmark(doc.path, store.cursor)) {
      BM.removeBookmark(doc.path, store.cursor);
      flash(`Removed bookmark at ${fmtOffsetHex(store.cursor)}`);
    } else if (BM.addBookmark(doc.path, store.cursor)) {
      flash(`Bookmarked ${fmtOffsetHex(store.cursor)}`);
    } else {
      flash("Bookmark already exists here");
    }
    store.navGen++;
  }

  let selLen = $derived(Math.max(0, store.selEnd - store.selStart));
</script>

<div class="statusbar">
  {#if doc}
    <div class="group goto">
      <button
        class="mini nav"
        onclick={goBack}
        disabled={!canBack}
        title="Back (Alt+Left)"
      >
        ←
      </button>
      <button
        class="mini nav"
        onclick={goForward}
        disabled={!canFwd}
        title="Forward (Alt+Right)"
      >
        →
      </button>
      {#if editing}
        <input
          class="goto-input"
          bind:this={inputEl}
          bind:value={expr}
          placeholder={store.t("goto.offset")}
          onblur={() => (editing = false)}
          onkeydown={(e) => {
            e.stopPropagation();
            if (e.key === "Enter") submit();
            if (e.key === "Escape") editing = false;
          }}
        />
      {:else}
        <button class="offset-btn" onclick={startEdit} title="{store.t('goto.title')} (Ctrl+G)">
          {store.t("status.offset")} {fmtOffsetHex(store.cursor)} ✎
        </button>
      {/if}
    </div>

    <div class="group" title="Selection range">
      {store.t("status.selection")}
      {#if selLen > 0}
        {fmtOffsetHex(store.selStart)}–{fmtOffsetHex(store.selEnd - 1)}
        <b>{selLen} B</b>
      {:else}
        —
      {/if}
      <button class="mini" onclick={copyOffset} title="Copy offset">⧉</button>
      <button
        class="mini star"
        class:on={starred}
        onclick={toggleBookmark}
        title="Toggle bookmark (Ctrl+D)"
      >
        {starred ? "★" : "☆"}
      </button>
      <button
        class="mini"
        onclick={() => (store.showBookmarks = true)}
        title="All bookmarks (Ctrl+Shift+B)"
      >
        ☰
      </button>
    </div>

    <div class="group">
      {store.t("status.size")} <b>{fmtSize(doc.size)}</b>
      {#if doc.dirty}<span class="badge dirty">● unsaved</span>{/if}
      {#if doc.overwriteOnly}<span class="badge">overwrite</span>{/if}
    </div>

    <div class="group">
      <span class="badge {doc.editingAllowed ? 'ok' : 'ro'}">
        {doc.editingAllowed ? store.t("status.editing") : store.t("status.readOnly")}
      </span>
      <span class="badge dim">{doc.profile}</span>
      <span class="badge dim">{doc.encoding}</span>
    </div>
  {:else}
    <div class="group">{store.t("app.title")}</div>
  {/if}

  <span class="spacer"></span>

  {#if store.progress}
    <div class="group progress">
      {store.progress.op}… <b>{store.progress.done}%</b>
      <span class="bar"><span style="width:{store.progress.done}%"></span></span>
    </div>
  {:else if store.statusMsg}
    <div class="group msg" role="status">{store.statusMsg}</div>
  {/if}

  <button
    class="ver"
    onclick={() => (store.showAbout = true)}
    title="About"
  >
    GoHex
  </button>
</div>

<style>
  .statusbar {
    display: flex;
    align-items: center;
    gap: 14px;
    height: var(--status-h);
    padding: 0 10px;
    background: var(--bg-panel);
    border-top: 1px solid var(--border);
    font-size: 11.5px;
    color: var(--text-dim);
    flex: none;
    white-space: nowrap;
    overflow: hidden;
  }

  .group {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .group b {
    color: var(--text);
    font-weight: 600;
  }

  .offset-btn {
    border: none;
    background: transparent;
    padding: 2px 6px;
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--accent);
    border-radius: 4px;
  }

  .offset-btn:hover {
    background: var(--accent-soft);
  }

  .goto-input {
    font-family: var(--font-mono);
    font-size: 11.5px;
    padding: 1px 6px;
    width: 220px;
  }

  .mini {
    border: none;
    background: transparent;
    padding: 0 3px;
    color: var(--text-dim);
  }

  .mini.nav:disabled {
    opacity: 0.35;
    cursor: default;
  }

  .mini.star.on {
    color: var(--accent);
  }

  .badge {
    padding: 1px 6px;
    border-radius: 8px;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    font-size: 10.5px;
  }

  .badge.ok {
    color: var(--ok);
    border-color: var(--ok);
  }

  .badge.ro {
    color: var(--danger);
    border-color: var(--danger);
  }

  .badge.dirty {
    color: var(--dirty);
    border-color: var(--dirty);
  }

  .badge.dim {
    opacity: 0.75;
  }

  .msg {
    color: var(--text);
    max-width: 46vw;
  }

  .progress .bar {
    width: 90px;
    height: 6px;
    background: var(--bg-raised);
    border-radius: 3px;
    overflow: hidden;
    display: inline-block;
  }

  .progress .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 0.2s;
  }

  .ver {
    border: none;
    background: transparent;
    color: var(--text-dim);
    font-size: 10.5px;
    padding: 2px 4px;
  }
</style>
