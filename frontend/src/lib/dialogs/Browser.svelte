<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type {
    Profile,
    Report,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/browser/models";
  import type { SaveResult } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";

  type Tab = "history" | "downloads" | "bookmarks";

  let root = $state("");
  let profiles = $state<Profile[]>([]);
  let sel = $state(0);
  let report = $state<Report | null>(null);
  let tab = $state<Tab>("history");
  let q = $state("");
  let format = $state("csv");
  let busy = $state(false);
  let error = $state("");
  let loaded = $state(false);

  let profile = $derived(sel >= 0 && sel < profiles.length ? profiles[sel] : null);
  let history = $derived(report?.history ?? []);
  let downloads = $derived(report?.downloads ?? []);
  let bookmarks = $derived(report?.bookmarks ?? []);

  let needle = $derived(q.trim().toLowerCase());
  let historyRows = $derived(
    history.filter((h) => !needle || match(h.url, h.title)),
  );
  let downloadRows = $derived(
    downloads.filter((d) => !needle || match(d.url, d.target, d.status)),
  );
  let bookmarkRows = $derived(
    bookmarks.filter((b) => !needle || match(b.path, b.title, b.url, String(b.kind))),
  );

  function match(...fields: string[]): boolean {
    return fields.some((f) => f.toLowerCase().includes(needle));
  }

  $effect(() => {
    if (!store.showBrowser || loaded) return;
    loaded = true;
    void scan();
  });

  async function scan(): Promise<void> {
    busy = true;
    error = "";
    try {
      profiles = (await svc.BrowserProfiles(root)) ?? [];
      sel = profiles.length > 0 ? 0 : -1;
      report = null;
      if (profiles.length === 0) {
        flash("No browser profiles found");
      } else {
        flash(`${profiles.length} profile${profiles.length === 1 ? "" : "s"} found`);
      }
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function chooseRoot(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Choose a home directory",
        CanChooseFiles: false,
        CanChooseDirectories: true,
        AllowsMultipleSelection: false,
      });
      const dir = Array.isArray(res) ? res[0] : res;
      if (!dir) return;
      root = dir;
      await scan();
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function read(): Promise<void> {
    if (!profile) return;
    busy = true;
    error = "";
    report = null;
    try {
      report = await svc.BrowserRead(profile);
      const w = report.warnings ?? [];
      flash(
        w.length
          ? `Read with ${w.length} warning${w.length === 1 ? "" : "s"}`
          : `Read ${profile.browser} profile "${profile.name}"`,
      );
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportCurrent(): Promise<void> {
    if (!profile) return;
    const name = `${profile.name}-${tab}.${format}`;
    let dst: string;
    try {
      const res = await Dialogs.SaveFile({ Title: "Export browser artifacts", Filename: name });
      dst = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Export dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const out: SaveResult = await svc.BrowserExport(profile, tab, format, dst);
      flash(`Exported ${out.bytesSaved} bytes → ${out.path} (sha256:${out.sha256})`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  // Times are rendered from the UTC fields so a report reads the same on
  // every machine that opens it.
  function fmtTime(iso: string): string {
    if (!iso || iso.startsWith("0001-01-01")) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const p = (n: number): string => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }

  function fmtSize(n: number): string {
    if (!n) return "—";
    if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)} GiB`;
    if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(2)} MiB`;
    if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
    return `${n} B`;
  }

  function bytes(d: { receivedBytes: number; totalBytes: number }): string {
    if (!d.receivedBytes && !d.totalBytes) return "—";
    if (d.totalBytes && d.receivedBytes && d.receivedBytes !== d.totalBytes) {
      return `${fmtSize(d.receivedBytes)} of ${fmtSize(d.totalBytes)}`;
    }
    return fmtSize(d.totalBytes || d.receivedBytes);
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Browser artifacts"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showBrowser = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showBrowser = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Browser artifacts</h2>
      <div class="head-actions">
        <button onclick={chooseRoot} disabled={busy}>Choose home…</button>
        <button onclick={() => void scan()} disabled={busy}>Rescan</button>
        <button class="primary" onclick={() => void read()} disabled={busy || !profile}>
          {busy ? "Working…" : "Read profile"}
        </button>
      </div>
    </div>

    <p class="intro">
      Extract web-browser artifacts from local profiles — Chrome, Chromium,
      Edge and Firefox. Pick a home directory (defaults to the current user),
      select a detected profile, then read its visited URLs (history),
      downloads and bookmark tree. Everything is opened strictly read-only.
    </p>

    <div class="options">
      <label class="field grow">
        <span>Home root</span>
        <input class="mono" placeholder="(current user)" bind:value={root} />
      </label>
      <label class="field grow">
        <span>Profile</span>
        <select bind:value={sel} disabled={profiles.length === 0}>
          {#each profiles as p, i}
            <option value={i}>{p.browser} — {p.name}</option>
          {/each}
        </select>
      </label>
    </div>

    {#if profile}
      <p class="meta"><span class="mono path">{profile.dir}</span></p>
    {/if}

    <div class="tabs">
      <button class:active={tab === "history"} onclick={() => (tab = "history")}>
        History <span class="count">{history.length}</span>
      </button>
      <button class:active={tab === "downloads"} onclick={() => (tab = "downloads")}>
        Downloads <span class="count">{downloads.length}</span>
      </button>
      <button class:active={tab === "bookmarks"} onclick={() => (tab = "bookmarks")}>
        Bookmarks <span class="count">{bookmarks.length}</span>
      </button>
      <span class="spacer"></span>
      <input class="filter" placeholder="Filter…" bind:value={q} />
      <select bind:value={format}>
        <option value="csv">CSV</option>
        <option value="json">JSON</option>
      </select>
      <button onclick={() => void exportCurrent()} disabled={busy || !report}>
        Export…
      </button>
    </div>

    {#if report && (report.warnings?.length ?? 0) > 0}
      <ul class="warns">
        {#each report.warnings as w}
          <li>{w}</li>
        {/each}
      </ul>
    {/if}

    <div class="scroll">
      <table>
        {#if tab === "history"}
          <thead>
            <tr>
              <th>URL</th><th>Title</th><th class="n">Visits</th><th class="n">Typed</th><th>Last visit</th>
            </tr>
          </thead>
          <tbody>
            {#if historyRows.length === 0}
              <tr class="none">
                <td colspan="5">
                  {report ? "No history matches this filter." : "Choose a profile and read it."}
                </td>
              </tr>
            {/if}
            {#each historyRows as h}
              <tr>
                <td class="mono url">{h.url}</td>
                <td>{h.title || "—"}</td>
                <td class="n">{h.visits}</td>
                <td class="n">{h.typed}</td>
                <td class="mono">{fmtTime(h.lastVisit)}</td>
              </tr>
            {/each}
          </tbody>
        {:else if tab === "downloads"}
          <thead>
            <tr>
              <th>Source</th><th>Target</th><th>Size</th><th>Start</th><th>End</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {#if downloadRows.length === 0}
              <tr class="none">
                <td colspan="6">
                  {report ? "No downloads match this filter." : "Choose a profile and read it."}
                </td>
              </tr>
            {/if}
            {#each downloadRows as d}
              <tr>
                <td class="mono url">{d.url || "—"}</td>
                <td class="mono url">{d.target || "—"}</td>
                <td>{bytes(d)}</td>
                <td class="mono">{fmtTime(d.start)}</td>
                <td class="mono">{fmtTime(d.end)}</td>
                <td>
                  {d.status || "unknown"}
                  {#if d.state >= 0 && !d.status}<span class="dim">({d.state})</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        {:else}
          <thead>
            <tr><th>Path</th><th>Title</th><th>Kind</th><th>URL</th><th>Added</th></tr>
          </thead>
          <tbody>
            {#if bookmarkRows.length === 0}
              <tr class="none">
                <td colspan="5">
                  {report ? "No bookmarks match this filter." : "Choose a profile and read it."}
                </td>
              </tr>
            {/if}
            {#each bookmarkRows as b}
              <tr>
                <td class="mono">{b.path || "—"}</td>
                <td>{b.title || "—"}</td>
                <td class="dim">{String(b.kind)}</td>
                <td class="mono url">{b.url || "—"}</td>
                <td class="mono">{fmtTime(b.added)}</td>
              </tr>
            {/each}
          </tbody>
        {/if}
      </table>
    </div>

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
    width: min(1080px, 96vw);
    max-height: 88vh;
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
    gap: 12px;
    margin-bottom: 10px;
  }

  .head-actions {
    display: flex;
    gap: 8px;
  }

  .intro {
    margin: 0 0 12px;
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--text-dim);
  }

  h2 {
    margin: 0;
    font-size: 18px;
    letter-spacing: 0.02em;
  }

  .meta {
    margin: 0 0 10px;
    font-size: 12.5px;
    color: var(--text-dim);
  }

  .path {
    color: var(--text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    max-width: 78ch;
    vertical-align: bottom;
  }

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
  }

  .options {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }

  .field {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-dim);
  }

  .field.grow {
    flex: 1;
    min-width: 260px;
  }

  .field input,
  .field select,
  .tabs select,
  .filter {
    padding: 4px 6px;
    font-size: 12.5px;
    background: var(--bg-input, transparent);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
  }

  .field input,
  .field select {
    flex: 1;
    min-width: 0;
  }

  .tabs {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }

  .tabs button {
    font-size: 12.5px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: transparent;
    color: var(--text-dim);
    cursor: pointer;
  }

  .tabs button.active {
    color: var(--text);
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 16%, transparent);
  }

  .count {
    font-family: var(--font-mono);
    opacity: 0.7;
  }

  .spacer {
    flex: 1;
  }

  .filter {
    width: 18ch;
  }

  .warns {
    margin: 0 0 8px;
    padding: 6px 10px 6px 26px;
    font-size: 12px;
    color: var(--dirty, #d9a441);
    background: color-mix(in srgb, var(--dirty, #d9a441) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--dirty, #d9a441) 40%, transparent);
    border-radius: 6px;
  }

  .scroll {
    overflow: auto;
    max-height: 52vh;
    border-top: 1px solid var(--border);
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 12.5px;
  }

  th {
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-dim);
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg-panel);
  }

  th.n,
  td.n {
    text-align: right;
  }

  td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    vertical-align: top;
  }

  td.url {
    max-width: 46ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  tr.none td {
    color: var(--text-dim);
    font-style: italic;
    white-space: normal;
    padding: 14px 8px;
  }

  .error {
    margin: 10px 0 0;
    color: var(--error, #e06c75);
    font-size: 12.5px;
  }
</style>
