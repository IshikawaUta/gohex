<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type { Report } from "../../../bindings/github.com/IshikawaUta/gohex/internal/dump/models";

  let path = $state("");
  let report = $state<Report | null>(null);
  let busy = $state(false);
  let error = $state("");

  async function choose(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open crash report",
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
        Filters: [
          {
            DisplayName: "Crash reports (ips, tombstone, wer)",
            Pattern: "*.ips;*tombstone*;*.wer;Report.wer;*.crash",
          },
          { DisplayName: "All files", Pattern: "*" },
        ],
      });
      const target = Array.isArray(res) ? res[0] : res;
      if (!target) return;
      path = target;
      report = null;
      error = "";
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function parse(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    report = null;
    try {
      report = await svc.DumpInfo(path);
      flash(`Crash report parsed — ${report.format} (${report.source})`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  const fields = $derived(
    report
      ? [
          ["Source", report.source],
          ["Format", report.format],
          ["Application", report.app],
          ["Version", report.version],
          ["Timestamp", report.timestamp],
          ["Type", report.type],
          ["PID / TID", report.pid ? `${report.pid} / ${report.tid || "-"}` : ""],
          ["Frames", report.frames ? String(report.frames) : ""],
        ].filter(([, v]) => v !== "" && v !== undefined)
      : [],
  );

  const details = $derived(
    report?.details ? Object.entries(report.details) : [],
  );
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Crash report parser"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showDump = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showDump = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Crash report</h2>
      <button class="primary" onclick={() => void parse()} disabled={busy || !path}>
        {busy ? "Parsing…" : "Parse"}
      </button>
    </div>

    <p class="meta">
      Parses a crash report read-only and shows its structured summary:
      macOS/iOS <span class="mono">.ips</span>, Android
      <span class="mono">tombstone</span> or Windows
      <span class="mono">WER</span>. Frames are reported verbatim — no
      symbolication is attempted.
    </p>

    <div class="options">
      <button onclick={() => void choose()} disabled={busy}>Open report…</button>
      {#if path}
        <span class="mono path">{path}</span>
      {/if}
    </div>

    {#if report}
      <div class="result-head">
        <span class="dim">{report.summary}</span>
        <span class="badge ok">parsed</span>
      </div>

      <dl class="fields">
        {#each fields as [label, value]}
          <dt>{label}</dt>
          <dd class="mono">{value}</dd>
        {/each}
      </dl>

      {#if details.length}
        <details class="extras" open={details.length <= 6}>
          <summary>Details ({details.length})</summary>
          <dl class="fields">
            {#each details as [k, v]}
              <dt>{k}</dt>
              <dd class="mono">{v}</dd>
            {/each}
          </dl>
        </details>
      {/if}

      {#if report.topFrames?.length}
        <h3>Top frames</h3>
        <pre class="output">{report.topFrames.join("\n")}</pre>
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

  h3 {
    margin: 14px 0 6px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-dim);
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
    margin-bottom: 8px;
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

  .fields {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 16px;
    margin: 0 0 10px;
    font-size: 12.5px;
  }

  .fields dt {
    color: var(--text-dim);
  }

  .fields dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .extras summary {
    cursor: pointer;
    font-size: 12.5px;
    color: var(--text-dim);
    margin-bottom: 6px;
  }

  .output {
    margin: 0;
    padding: 10px 12px;
    max-height: 30vh;
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
