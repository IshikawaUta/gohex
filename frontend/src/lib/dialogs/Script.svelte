<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type { ScriptResult } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";

  let path = $state("");
  let result = $state<ScriptResult | null>(null);
  let busy = $state(false);
  let error = $state("");

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open automation script",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
        Filters: [{ DisplayName: "Starlark scripts", Pattern: "*.star" }],
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (!target) return;
      path = target;
      result = null;
      error = "";
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function run(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    result = null;
    try {
      result = await svc.ScriptRun(path);
      if (result.error) {
        flash("Script failed — see the Script output");
      } else {
        flash(`Script finished — ${result.steps} steps in ${result.durationMs}ms`);
      }
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
  aria-label="Automation script runner"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showScript = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showScript = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Script</h2>
      <button class="primary" onclick={() => void run()} disabled={busy || !path}>
        {busy ? "Running…" : "Run"}
      </button>
    </div>

    <p class="meta">
      Runs a Starlark (.star) script with read-only access to the open
      documents through the <span class="mono">gohex</span> module
      (<span class="mono">docs / read / find / hash / version</span>).
      No filesystem, network or clock is exposed; every run is audited.
    </p>

    <div class="options">
      <button onclick={() => void choose()} disabled={busy}>Open script…</button>
      {#if path}
        <span class="mono path">{path}</span>
      {/if}
    </div>

    {#if result}
      <div class="result-head">
        <span class="dim">
          {result.steps} steps · {result.durationMs}ms
        </span>
        {#if result.error}
          <span class="badge fail">failed</span>
        {:else}
          <span class="badge ok">ok</span>
        {/if}
      </div>
    {/if}

    <pre class="output">{result
      ? [result.output, result.error].filter(Boolean).join("\n")
      : "Output of print() calls appears here."}</pre>

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
    width: min(760px, 94vw);
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

  .path {
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    max-width: 52ch;
    vertical-align: bottom;
  }

  .options {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 12px;
    font-size: 12.5px;
  }

  .result-head {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    margin-bottom: 6px;
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

  .output {
    margin: 0;
    padding: 10px 12px;
    min-height: 120px;
    max-height: 46vh;
    overflow: auto;
    font-family: var(--font-mono);
    font-size: 12.5px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
    background: color-mix(in srgb, var(--bg-input, #000) 60%, transparent);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
  }

  .error {
    margin: 10px 0 0;
    font-size: 12px;
    color: #e07b7b;
  }
</style>
