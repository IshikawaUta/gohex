<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { store, flash } from "./state.svelte";
  import { svc, models, Dialogs, errMsg } from "./api";
  import * as NM from "./macros";
  import type { Match } from "../../bindings/github.com/IshikawaUta/gohex/internal/hex/models";

  let mode = $state<"text" | "hex" | "regex">("text");
  let pattern = $state("");
  let patEl: HTMLInputElement | undefined = $state();
  onMount(() => {
    patEl?.focus();
    // F3 / Shift+F3 (search.next/prev) dispatched by the global keymap.
    store.findNavFn = (dir) => findSingle(dir);
  });
  onDestroy(() => {
    store.findNavFn = null;
  });
  let replacement = $state("");
  let caseFold = $state(true);
  let wrap = $state(true);
  let matches = $state<Match[]>([]);
  let searched = $state(false);

  let doc = $derived(store.active);

  let placeholder = $derived(
    mode === "hex" ? store.t("search.hex") : mode === "regex" ? store.t("search.regex") : store.t("search.text"),
  );

  function req(direction: "next" | "prev", max: number): models.FindRequest {
    return {
      id: doc!.id,
      mode,
      pattern,
      encoding: doc!.encoding,
      caseFold,
      direction,
      from: store.cursor,
      wrap,
      max,
    };
  }

  async function findSingle(direction: "next" | "prev"): Promise<void> {
    if (!doc || !pattern) return;
    try {
      const res = await svc.Find(req(direction, 0));
      const m = res.count > 0 ? (res.matches ?? [])[0] : undefined;
      if (m) {
        NM.record({ kind: "find", expr: pattern, forward: direction === "next", mode });
        store.revealFn?.(m.start, m.length);
        flash(`0x${m.start.toString(16).toUpperCase()} (+${m.length})`);
      } else {
        flash("Not found");
      }
    } catch (e) {
      flash(errMsg(e));
    }
  }

  async function findAll(): Promise<void> {
    if (!doc || !pattern) return;
    try {
      const res = await svc.Find(req("next", 500));
      matches = res.matches ?? [];
      searched = true;
      flash(res.truncated ? `First ${res.count} matches` : `${res.count} match(es)`);
      if (matches.length > 0) store.revealFn?.(matches[0].start, matches[0].length);
    } catch (e) {
      flash(errMsg(e));
    }
  }

  async function replaceAll(): Promise<void> {
    if (!doc || !pattern) return;
    try {
      const probe = await svc.Find(req("next", 500));
      if (probe.count === 0) {
        flash("Not found");
        return;
      }
      const ans = await Dialogs.Question({
        Title: store.t("search.replaceAll"),
        Message: `Replace ${probe.count}${probe.truncated ? "+" : ""} occurrence(s) of "${pattern}" with "${replacement}"?`,
      });
      if (ans !== "Yes") return;
      const n = await svc.ReplaceAll(doc.id, mode, pattern, replacement, doc.encoding, caseFold, true);
      matches = [];
      flash(`Replaced ${n} occurrence(s) — undo with Ctrl+Z`);
    } catch (e) {
      Dialogs.Error({ Title: store.t("search.replaceAll"), Message: errMsg(e) });
    }
  }

  function onKey(e: KeyboardEvent): void {
    e.stopPropagation();
    if (e.key === "Enter") findSingle(e.shiftKey ? "prev" : "next");
    if (e.key === "Escape") store.findOpen = false;
  }
</script>

<div class="findpanel" role="search">
  <div class="row">
    <select class="mode" bind:value={mode}>
      <option value="text" title={store.t("search.text")}>{store.t("search.short.text")}</option>
      <option value="hex" title={store.t("search.hex")}>{store.t("search.short.hex")}</option>
      <option value="regex" title={store.t("search.regex")}>{store.t("search.short.regex")}</option>
    </select>

    <input
      class="pat"
      bind:this={patEl}
      bind:value={pattern}
      placeholder={placeholder}
      onkeydown={onKey}
      oninput={() => {
        matches = [];
        searched = false;
      }}
    />

    {#if mode === "text"}
      <label class="chk" title={store.t("search.caseSensitive")}>
        <input type="checkbox" bind:checked={caseFold} />
        Aa
      </label>
    {/if}
    <label class="chk">
      <input type="checkbox" bind:checked={wrap} />
      wrap
    </label>

    <button class="fb" onclick={() => findSingle("prev")} disabled={!pattern} title="Shift+Enter">
      ⏴ {store.t("menu.search.prev")}
    </button>
    <button class="fb" onclick={() => findSingle("next")} disabled={!pattern} title="Enter">
      {store.t("menu.search.next")} ⏵
    </button>
    <button class="fb" onclick={findAll} disabled={!pattern} title="Find all (max 500)">
      ☰
    </button>

    <span class="spacer"></span>
    <button class="fb" onclick={() => (store.findOpen = false)}>✕</button>
  </div>

  <div class="row repl">
    <label for="repl-pat">{store.t("search.replaceWith")}</label>
    <input id="repl-pat" class="pat" bind:value={replacement} placeholder="…" onkeydown={onKey} />
    <button class="fb" onclick={replaceAll} disabled={!pattern || !store.editable} title="Requires editing permission">
      {store.t("search.replaceAll")}
    </button>
    {#if searched}
      <span class="count">{matches.length} shown</span>
    {/if}
  </div>

  {#if matches.length > 0}
    <div class="chips">
      {#each matches.slice(0, 200) as m, i (i)}
        <button class="chip" onclick={() => store.revealFn?.(m.start, m.length)}>
          0x{m.start.toString(16).toUpperCase()}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .findpanel {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 7px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border);
    flex: none;
  }

  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .mode {
    width: 100px;
    padding: 3px 6px;
    font-size: 12px;
    flex: none;
  }

  .pat {
    width: 340px;
    font-family: var(--font-mono);
    font-size: 12.5px;
  }

  .repl .pat {
    width: 340px;
  }

  .chk {
    display: flex;
    align-items: center;
    gap: 4px;
    color: var(--text-dim);
    font-size: 12px;
    cursor: pointer;
  }

  .fb {
    font-size: 12px;
    padding: 3px 8px;
  }

  .count {
    color: var(--text-dim);
    font-size: 11.5px;
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    max-height: 64px;
    overflow-y: auto;
  }

  .chip {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 1px 7px;
    border-radius: 9px;
  }
</style>
