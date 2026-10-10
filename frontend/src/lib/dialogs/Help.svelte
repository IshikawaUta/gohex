<script lang="ts">
  import { onMount } from "svelte";
  import { store, flash } from "../state.svelte";
  import { svc, errMsg } from "../api";
  import type { ShortcutHelp } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";

  let rows = $state<ShortcutHelp[]>([]);
  let filter = $state("");
  let sampleBusy = $state(false);
  let error = $state("");

  onMount(() => {
    void svc.ShortcutHelp().then((r) => (rows = r ?? [])).catch((e) => (error = errMsg(e)));
  });

  let visible = $derived(
    rows.filter(
      (r) =>
        !filter ||
        r.action.toLowerCase().includes(filter.toLowerCase()) ||
        (r.bound ?? "").toLowerCase().includes(filter.toLowerCase()),
    ),
  );

  async function loadSample(): Promise<void> {
    sampleBusy = true;
    error = "";
    try {
      const { Dialogs } = await import("../api");
      const dst = (await Dialogs.SaveFile({
        Title: "Save GoHex sample evidence",
        Filename: "gohex-sample.bin",
      })) as string;
      if (!dst) return;
      const res = await svc.CreateSampleFile(dst);
      store.showHelp = false;
      const { openFile } = await import("../actions");
      await openFile(dst);
      flash(`Sample evidence created (${res.bytesSaved} bytes, sha256:${(res.sha256 ?? "").slice(0, 16)}…)`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      sampleBusy = false;
    }
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Help"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showHelp = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showHelp = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Help &amp; shortcuts</h2>
      <button class="ghost" onclick={() => (store.showHelp = false)}>Close</button>
    </div>

    <section>
      <h3>Getting started</h3>
      <ul class="tour">
        <li><b>Open evidence</b> — Ctrl+O, drag &amp; drop onto the window, or the welcome-screen recent list. Images mount read-only.</li>
        <li><b>Navigate</b> — click the offset in the status bar (Ctrl+G accepts hex, dec, or expressions); Alt+Left/Right walks back/forward.</li>
        <li><b>Bookmarks</b> — Ctrl+D marks the cursor; Ctrl+Shift+B lists them. Bookmarks persist per file.</li>
        <li><b>Forensics</b> — Tools → Disk (partitions, filesystem, clone, FUSE mount, NTFS ADS), Carve, Memory triage, Case + timeline + PDF/DOCX reports, RAID assembly, Utilities.</li>
        <li><b>Macros</b> — Tools → Macro records navigation/find/copy/bookmark for replay against similar evidence.</li>
        <li><b>Evidence safety</b> — everything is read-only by default; writes need an explicit edit profile and are audited.</li>
      </ul>
      <button class="primary" onclick={() => void loadSample()} disabled={sampleBusy}>
        {sampleBusy ? "Creating…" : "Load sample evidence file…"}
      </button>
      <p class="dim small">
        Generates a 64 KiB synthetic training image (MZ header, PNG/JPEG/ZIP
        signatures, entropy regions, UTF-16 strings, find markers). Nothing
        comes from a real system.
      </p>
    </section>

    <section>
      <h3>Keyboard shortcuts</h3>
      <input
        class="filter"
        bind:value={filter}
        placeholder="Filter by action or chord…"
      />
      <table>
        <thead>
          <tr><th>Action</th><th>Your binding</th><th>Default</th></tr>
        </thead>
        <tbody>
          {#each visible as r (r.action)}
            <tr>
              <td class="mono">{r.action}</td>
              <td class="mono chord">{r.bound || "—"}</td>
              <td class="mono dim">{r.default || "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="dim small">
        Bindings are editable in Preferences. Chords use the canonical form
        Ctrl+Alt+Shift+Meta+Key.
      </p>
    </section>

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
    width: min(720px, 96vw);
    max-height: 84vh;
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
    margin-bottom: 8px;
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  h3 {
    margin: 14px 0 6px;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-dim);
  }
  section {
    margin-bottom: 6px;
  }
  .tour {
    margin: 0 0 10px;
    padding-left: 18px;
    font-size: 12.5px;
    line-height: 1.6;
    color: var(--text);
  }
  .filter {
    width: 100%;
    font-size: 12.5px;
    padding: 4px 8px;
    margin-bottom: 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-input, transparent);
    color: var(--text);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }
  th,
  td {
    text-align: left;
    padding: 3px 8px;
    border-bottom: 1px solid var(--border);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .chord {
    color: var(--accent);
  }
  .dim {
    color: var(--text-dim);
  }
  .small {
    font-size: 11.5px;
    margin: 6px 0 0;
  }
  .ghost {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
  }
  .error {
    color: var(--danger, #e5534b);
    margin-top: 8px;
  }
</style>
