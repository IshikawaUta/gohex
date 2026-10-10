<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, errMsg } from "../api";
  import type { Result } from "../../../bindings/github.com/IshikawaUta/gohex/internal/compare/models";
  import { fmtOffsetHex, fmtSize } from "../format";

  // Up to four documents: A is the reference, B/C/D are optional
  // partners. Each pair is compared client-side via the 2-way service.
  let pickA = $state<number | null>(null);
  let pickB = $state<number | null>(null);
  let pickC = $state<number | null>(null);
  let pickD = $state<number | null>(null);
  let pair = $state<"AB" | "AC" | "AD">("AB");
  let results = $state<Record<string, Result | null>>({ AB: null, AC: null, AD: null });
  let busy = $state(false);
  let error = $state("");

  let activeResult = $derived(results[pair] ?? null);
  let canRun = $derived(
    pickA !== null &&
      [pickB, pickC, pickD].some((p) => p !== null && p !== pickA),
  );

  $effect(() => {
    if (store.showCompare) {
      const docs = store.docs;
      if (pickA === null && docs.length > 0) pickA = docs[0].id;
      if (pickB === null && docs.length > 1) pickB = docs[1].id;
      if (pickC === null && docs.length > 2) pickC = docs[2].id;
      if (pickD === null && docs.length > 3) pickD = docs[3].id;
    } else {
      pickA = null;
      pickB = null;
      pickC = null;
      pickD = null;
      results = { AB: null, AC: null, AD: null };
      error = "";
    }
  });

  function docName(id: number | null): string {
    return store.docs.find((d) => d.id === id)?.name ?? "—";
  }

  async function runPair(key: "AB" | "AC" | "AD", a: number, b: number): Promise<void> {
    results = { ...results, [key]: await svc.CompareDocuments(a, b) };
  }

  async function run(): Promise<void> {
    if (pickA === null) return;
    busy = true;
    error = "";
    results = { AB: null, AC: null, AD: null };
    try {
      if (pickB !== null && pickB !== pickA) await runPair("AB", pickA, pickB);
      if (pickC !== null && pickC !== pickA) await runPair("AC", pickA, pickC);
      if (pickD !== null && pickD !== pickA) await runPair("AD", pickA, pickD);
      const r = activeResult;
      if (r) {
        flash(
          r.identical
            ? "Compare: documents are identical"
            : `Compare: first difference at ${fmtOffsetHex(r.firstDiff)}`,
        );
      }
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  /** revealIn switches the active document and jumps to off. */
  async function revealIn(docId: number, off: number): Promise<void> {
    store.activeId = docId;
    // Wait a tick so HexView remounts and registers revealFn.
    requestAnimationFrame(() => {
      store.revealFn?.(off);
      store.navGen++;
    });
  }

  /** revealBoth jumps A then B at the same offset — synchronized reveal. */
  async function revealBoth(start: number): Promise<void> {
    const bId = pair === "AB" ? pickB : pair === "AC" ? pickC : pickD;
    if (pickA === null || bId === null) return;
    await revealIn(pickA, start);
    setTimeout(() => void revealIn(bId, start), 80);
    flash(`Synced both documents at ${fmtOffsetHex(start)}`);
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Binary compare"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showCompare = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showCompare = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Compare</h2>
      <button
        class="primary"
        onclick={() => void run()}
        disabled={busy || !canRun}
      >
        {busy ? "Comparing…" : "Compare"}
      </button>
    </div>

    <p class="meta">
      Byte-compares open documents read-only (reference A against B, C, and
      D) and lists the differing ranges. Identical blocks are skipped in
      64 KiB chunks; only differing regions are scanned byte by byte. Use
      ⇔ sync to reveal a difference in BOTH documents at once.
    </p>

    <div class="picks">
      <label>
        A (reference)
        <select bind:value={pickA} disabled={busy}>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
      <label>
        B
        <select bind:value={pickB} disabled={busy}>
          <option value={null}>— none —</option>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
      <label>
        C
        <select bind:value={pickC} disabled={busy}>
          <option value={null}>— none —</option>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
      <label>
        D
        <select bind:value={pickD} disabled={busy}>
          <option value={null}>— none —</option>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
    </div>

    {#if pickA !== null && pickA === pickB}
      <p class="warn">Pick two different documents (or clear B).</p>
    {/if}

    {#if results.AB || results.AC || results.AD}
      <div class="pairtabs">
        {#if results.AB}
          <button class:sel={pair === "AB"} onclick={() => (pair = "AB")}>
            A×B {docName(pickB)}
          </button>
        {/if}
        {#if results.AC}
          <button class:sel={pair === "AC"} onclick={() => (pair = "AC")}>
            A×C {docName(pickC)}
          </button>
        {/if}
        {#if results.AD}
          <button class:sel={pair === "AD"} onclick={() => (pair = "AD")}>
            A×D {docName(pickD)}
          </button>
        {/if}
      </div>
    {/if}

    {#if activeResult}
      <div class="result-head">
        {#if activeResult.identical}
          <span class="badge ok">identical</span>
          <span class="dim">both documents match for {fmtSize(activeResult.sizeA)} bytes</span>
        {:else}
          <span class="badge fail"
            >{activeResult.ranges?.length ?? 0}{activeResult.truncated ? "+" : ""} range(s)</span
          >
          <span class="dim">
            first difference at {fmtOffsetHex(activeResult.firstDiff)} ·
            {fmtSize(activeResult.equal)} equal · {fmtSize(activeResult.differing)} differing
            {#if activeResult.truncated}(range list truncated, counts exact){/if}
          </span>
        {/if}
      </div>

      {#if !activeResult.identical && activeResult.ranges?.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Start</th>
                <th>Length</th>
                <th>Size</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each activeResult.ranges as r, i}
                <tr>
                  <td class="dim">{i + 1}</td>
                  <td class="mono">{fmtOffsetHex(r.start)}</td>
                  <td class="mono">{fmtOffsetHex(r.length)}</td>
                  <td class="dim">{fmtSize(r.length)}</td>
                  <td class="ops">
                    <button
                      class="mini"
                      title="Jump reference document A to this difference"
                      onclick={() => {
                        if (pickA !== null) void revealIn(pickA, r.start);
                      }}
                    >
                      A
                    </button>
                    <button
                      class="mini"
                      title="Jump the partner document to this difference"
                      onclick={() => {
                        const bId = pair === "AB" ? pickB : pair === "AC" ? pickC : pickD;
                        if (bId !== null) void revealIn(bId, r.start);
                      }}
                    >
                      B/C/D
                    </button>
                    <button
                      class="mini sync"
                      title="Synchronized reveal: jump BOTH documents here"
                      onclick={() => void revealBoth(r.start)}
                    >
                      ⇔ sync
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
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
    width: min(720px, 94vw);
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

  .picks {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 12px;
    font-size: 12.5px;
  }

  .picks label {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-dim);
  }

  select {
    max-width: 28ch;
  }

  .warn {
    margin: 0 0 10px;
    font-size: 12.5px;
    color: #e0b07b;
  }

  .pairtabs {
    display: flex;
    gap: 6px;
    margin-bottom: 8px;
    flex-wrap: wrap;
  }

  .pairtabs button {
    font-size: 12px;
    padding: 3px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: transparent;
    color: var(--text-dim);
    cursor: pointer;
  }

  .pairtabs button.sel {
    border-color: var(--accent);
    color: var(--accent);
  }

  .ops {
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

  .mini:hover {
    color: var(--text);
  }

  .mini.sync {
    color: var(--accent);
    border-color: var(--accent);
  }

  .result-head {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    margin-bottom: 8px;
    flex-wrap: wrap;
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

  .badge.fail {
    border-color: #e07b7b;
    color: #e07b7b;
    background: color-mix(in srgb, #e07b7b 14%, transparent);
  }

  .table-wrap {
    max-height: 44vh;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }

  th,
  td {
    text-align: left;
    padding: 5px 10px;
    border-bottom: 1px solid var(--border);
  }

  th {
    position: sticky;
    top: 0;
    background: var(--bg-panel);
    color: var(--text-dim);
    font-weight: 600;
    font-size: 11.5px;
    letter-spacing: 0.04em;
  }

  tr:last-child td {
    border-bottom: none;
  }

  .error {
    margin: 10px 0 0;
    font-size: 12px;
    color: #e07b7b;
  }
</style>
