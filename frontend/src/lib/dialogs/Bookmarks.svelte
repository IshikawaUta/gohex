<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { fmtOffsetHex } from "../format";
  import * as BM from "../bookmarks";
  import * as NH from "../navhist";

  let doc = $derived(store.active);
  let path = $derived(doc?.path ?? "");
  let list = $state<BM.Bookmark[]>([]);
  let label = $state("");

  $effect(() => {
    if (path) list = BM.bookmarksFor(path);
  });

  function refresh(): void {
    if (path) list = BM.bookmarksFor(path);
  }

  function jump(b: BM.Bookmark): void {
    if (doc) {
      NH.push(doc.id, b.offset);
      store.navGen++;
    }
    store.revealFn?.(b.offset);
    store.showBookmarks = false;
    flash(`Jumped to bookmark ${b.label}`);
  }

  function remove(b: BM.Bookmark): void {
    if (!path) return;
    BM.removeBookmark(path, b.offset);
    refresh();
  }

  function add(): void {
    if (!doc || !path) {
      flash("Save the file first — bookmarks are keyed by path");
      return;
    }
    if (BM.addBookmark(path, store.cursor, label)) {
      flash(`Bookmarked ${fmtOffsetHex(store.cursor)}`);
    } else {
      flash("Bookmark already exists here");
    }
    label = "";
    refresh();
  }

  function fmtCreated(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Bookmarks"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showBookmarks = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showBookmarks = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Bookmarks</h2>
      <button class="ghost" onclick={() => (store.showBookmarks = false)}>Close</button>
    </div>
    {#if doc}
      <p class="meta">
        Named offsets in <b>{doc.name}</b>. Click a row to jump; Ctrl+D bookmarks the
        current cursor offset.
      </p>
      <div class="addbar">
        <input
          bind:value={label}
          placeholder="Label (optional)"
          onkeydown={(e) => {
            if (e.key === "Enter") add();
          }}
        />
        <button class="primary" onclick={add}>Bookmark {fmtOffsetHex(store.cursor)}</button>
      </div>
      {#if list.length}
        <table>
          <thead>
            <tr><th>Offset</th><th>Label</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {#each list as b (b.offset)}
              <tr class="click" onclick={() => jump(b)}>
                <td class="mono">{fmtOffsetHex(b.offset)}</td>
                <td>{b.label}</td>
                <td class="dim">{fmtCreated(b.created)}</td>
                <td>
                  <button
                    class="ghost"
                    onclick={(e) => {
                      e.stopPropagation();
                      remove(b);
                    }}
                  >
                    ✕
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="dim">No bookmarks in this file yet.</p>
      {/if}
    {:else}
      <p class="dim">Open a file to use bookmarks.</p>
    {/if}
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
    width: min(640px, 96vw);
    max-height: 76vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
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
  .meta {
    margin: 0 0 10px;
    font-size: 12.5px;
    color: var(--text-dim);
  }
  .addbar {
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
  }
  .addbar input {
    flex: 1;
    font-size: 12.5px;
    padding: 4px 8px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-input, transparent);
    color: var(--text);
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
  .mono {
    font-family: var(--font-mono);
  }
  .dim {
    color: var(--text-dim);
    font-size: 12.5px;
  }
  .click {
    cursor: pointer;
  }
  .click:hover td {
    background: var(--accent-soft);
  }
  .ghost {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 2px 8px;
    border-radius: 6px;
    cursor: pointer;
  }
</style>
