<script lang="ts">
  import { store } from "./state.svelte";
  import * as A from "./actions";

  function activate(id: number): void {
    if (store.activeId === id) return;
    store.activeId = id;
    A.syncSelectionFromDoc();
    requestAnimationFrame(() => {
      const d = store.active;
      if (d) store.revealFn?.(d.cursor);
    });
  }
</script>

<div class="tabbar">
  {#each store.docs as d (d.id)}
    <div
      class="tab"
      class:active={d.id === store.activeId}
      onclick={() => activate(d.id)}
      onauxclick={(e) => {
        if (e.button === 1) A.closeDocument(d.id);
      }}
      role="tab"
      aria-selected={d.id === store.activeId}
      tabindex="0"
      onkeydown={(e) => {
        if (e.key === "Enter" || e.key === " ") activate(d.id);
      }}
      title={d.path || "Untitled"}
    >
      {#if d.dirty}<span class="dot" title="Unsaved changes"></span>{/if}
      <span class="name">{d.name || "Untitled"}</span>
      <button
        class="x"
        title={store.t("menu.file.close")}
        onclick={(e) => {
          e.stopPropagation();
          A.closeDocument(d.id);
        }}
      >
        ×
      </button>
    </div>
  {/each}
  <button class="add" title="New document" onclick={() => A.newDocument()}>+</button>
</div>

<style>
  .tabbar {
    display: flex;
    align-items: stretch;
    gap: 2px;
    height: var(--tabbar-h);
    padding: 3px 6px 0;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    flex: none;
  }

  .tab {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 8px;
    max-width: 220px;
    border: 1px solid transparent;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    cursor: pointer;
    color: var(--text-dim);
    font-size: 12px;
    white-space: nowrap;
  }

  .tab:hover {
    background: var(--bg-raised);
  }

  .tab.active {
    background: var(--bg);
    border-color: var(--border);
    color: var(--text);
  }

  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--dirty);
    flex: none;
  }

  .name {
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .x {
    border: none;
    background: transparent;
    padding: 0 2px;
    font-size: 14px;
    line-height: 1;
    color: var(--text-dim);
    border-radius: 3px;
  }

  .x:hover {
    background: var(--danger);
    color: #fff;
  }

  .add {
    border: 1px dashed var(--border);
    background: transparent;
    padding: 0 10px;
    font-size: 14px;
    color: var(--text-dim);
    align-self: center;
    height: 22px;
  }
</style>
