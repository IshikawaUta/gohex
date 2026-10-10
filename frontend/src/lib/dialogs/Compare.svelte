<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, errMsg } from "../api";
  import type { Result } from "../../../bindings/github.com/IshikawaUta/gohex/internal/compare/models";
  import { fmtOffsetHex, fmtSize } from "../format";

  let pickA = $state<number | null>(null);
  let pickB = $state<number | null>(null);
  let result = $state<Result | null>(null);
  let busy = $state(false);
  let error = $state("");

  $effect(() => {
    if (store.showCompare && !result && !busy) {
      const docs = store.docs;
      if (pickA === null && docs.length > 0) pickA = docs[0].id;
      if (pickB === null && docs.length > 1) pickB = docs[1].id;
    }
    if (!store.showCompare) {
      pickA = null;
      pickB = null;
      result = null;
      error = "";
    }
  });

  async function run(): Promise<void> {
    if (pickA === null || pickB === null) return;
    busy = true;
    error = "";
    result = null;
    try {
      result = await svc.CompareDocuments(pickA, pickB);
      flash(
        result.identical
          ? "Compare: documents are identical"
          : `Compare: first difference at ${fmtOffsetHex(result.firstDiff)}`,
      );
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
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
        disabled={busy || pickA === null || pickB === null || pickA === pickB}
      >
        {busy ? "Comparing…" : "Compare"}
      </button>
    </div>

    <p class="meta">
      Byte-compares two open documents read-only and lists the differing
      ranges. Identical blocks are skipped in 64 KiB chunks; only differing
      regions are scanned byte by byte.
    </p>

    <div class="picks">
      <label>
        A
        <select bind:value={pickA} disabled={busy}>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
      <label>
        B
        <select bind:value={pickB} disabled={busy}>
          {#each store.docs as d (d.id)}
            <option value={d.id}>{d.name}</option>
          {/each}
        </select>
      </label>
    </div>

    {#if pickA !== null && pickA === pickB}
      <p class="warn">Pick two different documents.</p>
    {/if}

    {#if result}
      <div class="result-head">
        {#if result.identical}
          <span class="badge ok">identical</span>
          <span class="dim">both documents match for {fmtSize(result.sizeA)} bytes</span>
        {:else}
          <span class="badge fail">{result.ranges?.length ?? 0}{result.truncated ? "+" : ""} range(s)</span>
          <span class="dim">
            first difference at {fmtOffsetHex(result.firstDiff)} ·
            {fmtSize(result.equal)} equal · {fmtSize(result.differing)} differing
            {#if result.truncated}(range list truncated, counts exact){/if}
          </span>
        {/if}
      </div>

      {#if !result.identical && result.ranges?.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Start</th>
                <th>Length</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each result.ranges as r, i}
                <tr>
                  <td class="dim">{i + 1}</td>
                  <td class="mono">{fmtOffsetHex(r.start)}</td>
                  <td class="mono">{fmtOffsetHex(r.length)}</td>
                  <td class="dim">{fmtSize(r.length)}</td>
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
