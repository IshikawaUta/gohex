<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type {
    CaseState,
    SaveResult,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/service/models";
  import type {
    Case,
    VerifyResult,
    Event as CaseEvent,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/forensics/models";

  type Tab = "evidence" | "findings" | "timeline";

  let caseState = $state<CaseState | null>(null);
  let tab: Tab = $state("evidence");
  let busy = $state(false);
  let error = $state("");
  let loaded = $state(false);
  let verify = $state<VerifyResult | null>(null);

  // Case metadata form (used both to create a case and to edit one).
  let name = $state("");
  let examiner = $state("");
  let description = $state("");

  // Evidence form.
  let evKind = $state("image");
  let evNote = $state("");

  // Finding form.
  let fTitle = $state("");
  let fDetail = $state("");
  let fSeverity = $state("info");
  let fEvidence = $state("");

  // Event form.
  let eTime = $state(defaultTime());
  let eKind = $state("manual");
  let eSource = $state("");
  let eSummary = $state("");
  let eEvidence = $state("");

  let cse = $derived(caseState?.case ?? null);
  let evidence = $derived(cse?.evidence ?? []);
  let findings = $derived(cse?.findings ?? []);
  let events = $derived(sortEvents(cse?.events ?? []));
  let reportFormat = $state("html");

  $effect(() => {
    if (!store.showCase || loaded) return;
    loaded = true;
    void refresh();
  });

  function defaultTime(): string {
    const d = new Date();
    const p = (n: number): string => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  async function refresh(): Promise<void> {
    try {
      caseState = await svc.CaseState();
      name = cse?.name ?? "";
      examiner = cse?.examiner ?? "";
      description = cse?.description ?? "";
      error = "";
    } catch (e) {
      error = errMsg(e);
    }
  }

  // Events are stored in insertion order; the report and the table agree on
  // oldest-first with undated entries last.
  function sortEvents(list: CaseEvent[]): CaseEvent[] {
    return [...list].sort((a, b) => {
      const at = a.time ? Date.parse(a.time) : Number.NaN;
      const bt = b.time ? Date.parse(b.time) : Number.NaN;
      const au = Number.isNaN(at);
      const bu = Number.isNaN(bt);
      if (au !== bu) return au ? 1 : -1;
      if (au && bu) return 0;
      return at - bt;
    });
  }

  async function newCase(): Promise<void> {
    busy = true;
    error = "";
    try {
      caseState = await svc.CaseNew(name, examiner, description);
      flash(`Case "${caseState.case?.name}" opened`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function openCase(): Promise<void> {
    let path: string;
    try {
      const res = await Dialogs.OpenFile({
        Title: "Open case",
        Filters: [{ DisplayName: "GoHex case", Pattern: "*.json" }],
      });
      path = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!path) return;
    busy = true;
    error = "";
    try {
      caseState = await svc.CaseOpen(path);
      flash(`Opened ${path}`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
      await refresh();
    }
  }

  async function closeCase(): Promise<void> {
    busy = true;
    error = "";
    try {
      await svc.CaseClose();
      await refresh();
      flash("Case closed");
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function applyMeta(): Promise<void> {
    if (!cse) return;
    busy = true;
    error = "";
    try {
      caseState = await svc.CaseSetMeta(name, examiner, description);
      flash("Case details updated");
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function saveCase(): Promise<void> {
    if (!cse) return;
    let path: string;
    try {
      const res = await Dialogs.SaveFile({
        Title: "Save case",
        Filename: `${cse.name.replace(/[^\w.-]+/g, "_")}.json`,
      });
      path = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!path) return;
    busy = true;
    error = "";
    try {
      const r: SaveResult = await svc.CaseSave(path);
      await refresh();
      flash(`Saved ${r.bytesSaved} bytes → ${r.path} (sha256:${r.sha256})`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function addEvidence(): Promise<void> {
    let picked: string[] = [];
    try {
      const res = await Dialogs.OpenFile({
        Title: "Add evidence",
        AllowsMultipleSelection: true,
      });
      picked = Array.isArray(res) ? res : res ? [res] : [];
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
      return;
    }
    if (picked.length === 0) return;
    busy = true;
    error = "";
    try {
      for (const p of picked) {
        caseState = await svc.CaseEvidenceAdd(p, evKind, evNote);
      }
      flash(
        `${picked.length} item${picked.length === 1 ? "" : "s"} added, hashed and recorded`,
      );
      evNote = "";
      tab = "evidence";
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function verifyOne(id: string): Promise<void> {
    busy = true;
    error = "";
    try {
      verify = await svc.CaseEvidenceVerify(id);
      flash(
        verify.match
          ? `${verify.evidenceId} matches the recorded digest`
          : `${verify.evidenceId} DOES NOT MATCH — evidence changed since it was added`,
      );
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function verifyAll(): Promise<void> {
    if (evidence.length === 0) return;
    busy = true;
    error = "";
    let ok = 0;
    let bad = 0;
    try {
      for (const e of evidence) {
        const r = await svc.CaseEvidenceVerify(e.id);
        verify = r;
        if (r.match) ok++;
        else bad++;
      }
      flash(
        bad === 0
          ? `All ${ok} evidence digest${ok === 1 ? "" : "s"} match`
          : `${bad} of ${ok + bad} evidence files DO NOT MATCH`,
      );
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function addFinding(): Promise<void> {
    if (!cse) return;
    busy = true;
    error = "";
    try {
      caseState = await svc.CaseFindingAdd({
        title: fTitle,
        detail: fDetail,
        severity: fSeverity,
        evidenceId: fEvidence,
      });
      fTitle = "";
      fDetail = "";
      fEvidence = "";
      flash("Finding recorded");
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function addEvent(): Promise<void> {
    if (!cse) return;
    busy = true;
    error = "";
    try {
      const when = eTime ? new Date(eTime).toISOString() : new Date().toISOString();
      caseState = await svc.CaseEventAdd({
        time: when,
        source: eSource,
        kind: eKind,
        summary: eSummary,
        evidenceId: eEvidence,
      });
      eSummary = "";
      eSource = "";
      flash("Timeline event added");
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportReport(): Promise<void> {
    if (!cse) return;
    let path: string;
    try {
      const res = await Dialogs.SaveFile({
        Title: "Export report",
        Filename: `${cse.name.replace(/[^\w.-]+/g, "_")}_report.${reportFormat}`,
      });
      path = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!path) return;
    busy = true;
    error = "";
    try {
      const r: SaveResult = await svc.CaseReport(reportFormat, path);
      flash(`Report written: ${r.bytesSaved} bytes → ${r.path} (sha256:${r.sha256})`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function when(iso: string): string {
    if (!iso || iso.startsWith("0001-01-01")) return "not recorded";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const p = (n: number): string => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
  }

  function fmtSize(n: number): string {
    if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)} GiB`;
    if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(2)} MiB`;
    if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
    return `${n} B`;
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Forensic case"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showCase = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showCase = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Case</h2>
      <div class="head-actions">
        {#if cse}
          <button onclick={() => void saveCase()} disabled={busy}>Save case…</button>
          <button class="primary" onclick={() => void closeCase()} disabled={busy}>Close</button>
        {:else}
          <button onclick={() => void openCase()} disabled={busy}>Open case…</button>
        {/if}
      </div>
    </div>

    <div class="options">
      <label class="field grow">
        <span>Name</span>
        <input bind:value={name} placeholder="Operation Nightfall" />
      </label>
      <label class="field grow">
        <span>Examiner</span>
        <input bind:value={examiner} placeholder="name / badge" />
      </label>
      {#if cse}
        <button onclick={() => void applyMeta()} disabled={busy}>Apply</button>
      {/if}
    </div>
    <div class="options">
      <label class="field grow">
        <span>Description</span>
        <input bind:value={description} placeholder="what this case is about" />
      </label>
      {#if !cse}
        <button class="primary" onclick={() => void newCase()} disabled={busy || !name.trim()}>
          New case
        </button>
      {/if}
    </div>

    {#if cse}
      <p class="meta">
        <span class="mono">{cse.id}</span>
        {#if caseState?.path}<span class="dim"> · {caseState.path}</span>{/if}
        <span class="dim"> · opened {when(cse.createdAt)}</span>
      </p>

      <div class="tabs">
        <button class:active={tab === "evidence"} onclick={() => (tab = "evidence")}>
          Evidence <span class="count">{evidence.length}</span>
        </button>
        <button class:active={tab === "findings"} onclick={() => (tab = "findings")}>
          Findings <span class="count">{findings.length}</span>
        </button>
        <button class:active={tab === "timeline"} onclick={() => (tab = "timeline")}>
          Timeline <span class="count">{events.length}</span>
        </button>
        <span class="spacer"></span>
        <select bind:value={reportFormat} title="Report format">
          <option value="html">HTML</option>
          <option value="json">JSON</option>
          <option value="pdf">PDF</option>
          <option value="docx">DOCX</option>
        </select>
        <button onclick={() => void exportReport()} disabled={busy}>Export report…</button>
      </div>

      {#if tab === "evidence"}
        <div class="bar">
          <label class="field">
            <span>Kind</span>
            <select bind:value={evKind}>
              <option value="image">image</option>
              <option value="file">file</option>
              <option value="carved">carved</option>
              <option value="export">export</option>
              <option value="other">other</option>
            </select>
          </label>
          <label class="field grow">
            <span>Note</span>
            <input bind:value={evNote} placeholder="optional" />
          </label>
          <button onclick={() => void addEvidence()} disabled={busy}>Add evidence…</button>
          <button onclick={() => void verifyAll()} disabled={busy || evidence.length === 0}>
            Verify all
          </button>
        </div>
        <div class="scroll">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Kind</th><th>Path</th><th>Size</th><th>SHA-256</th><th>Added</th><th></th>
              </tr>
            </thead>
            <tbody>
              {#if evidence.length === 0}
                <tr class="none"><td colspan="7">No evidence yet — add the files you examined.</td></tr>
              {/if}
              {#each evidence as e (e.id)}
                <tr>
                  <td class="mono">{e.id}</td>
                  <td>{e.kind}</td>
                  <td class="mono url" title={e.path}>{e.path}</td>
                  <td>{fmtSize(e.size)}</td>
                  <td class="mono hash">
                    {e.sha256 ? `${e.sha256.slice(0, 16)}…` : "—"}
                    {#if verify && verify.evidenceId === e.id}
                      <span class:bad={!verify.match} class="verdict">
                        {verify.match ? "✓ match" : "✗ MISMATCH"}
                      </span>
                    {/if}
                  </td>
                  <td class="mono">{when(e.addedAt)}</td>
                  <td><button onclick={() => void verifyOne(e.id)} disabled={busy}>Verify</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else if tab === "findings"}
        <div class="bar">
          <label class="field grow">
            <span>Title</span>
            <input bind:value={fTitle} placeholder="what you concluded" />
          </label>
          <label class="field">
            <span>Severity</span>
            <select bind:value={fSeverity}>
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label class="field">
            <span>Evidence</span>
            <select bind:value={fEvidence}>
              <option value="">—</option>
              {#each evidence as e (e.id)}
                <option value={e.id}>{e.id}</option>
              {/each}
            </select>
          </label>
          <button class="primary" onclick={() => void addFinding()} disabled={busy || !fTitle.trim()}>
            Add finding
          </button>
        </div>
        <label class="field full">
          <span>Detail</span>
          <input bind:value={fDetail} placeholder="supporting detail" />
        </label>
        <div class="scroll">
          <table>
            <thead>
              <tr><th>ID</th><th>Severity</th><th>Title</th><th>Detail</th><th>Evidence</th><th>Recorded</th></tr>
            </thead>
            <tbody>
              {#if findings.length === 0}
                <tr class="none"><td colspan="6">No findings recorded.</td></tr>
              {/if}
              {#each findings as f (f.id)}
                <tr>
                  <td class="mono">{f.id}</td>
                  <td><span class={"sev sev-" + f.severity}>{f.severity}</span></td>
                  <td>{f.title}</td>
                  <td class="dim">{f.detail || "—"}</td>
                  <td class="mono">{f.evidenceId || "—"}</td>
                  <td class="mono">{when(f.createdAt)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="bar">
          <label class="field">
            <span>Time</span>
            <input type="datetime-local" bind:value={eTime} />
          </label>
          <label class="field">
            <span>Kind</span>
            <select bind:value={eKind}>
              <option value="manual">manual</option>
              <option value="visit">visit</option>
              <option value="download">download</option>
              <option value="fs">fs</option>
              <option value="carve">carve</option>
              <option value="evidence">evidence</option>
              <option value="export">export</option>
            </select>
          </label>
          <label class="field">
            <span>Source</span>
            <input bind:value={eSource} placeholder="browser:Chrome" />
          </label>
          <label class="field">
            <span>Evidence</span>
            <select bind:value={eEvidence}>
              <option value="">—</option>
              {#each evidence as e (e.id)}
                <option value={e.id}>{e.id}</option>
              {/each}
            </select>
          </label>
        </div>
        <div class="bar">
          <label class="field grow">
            <span>Summary</span>
            <input bind:value={eSummary} placeholder="what happened" />
          </label>
          <button class="primary" onclick={() => void addEvent()} disabled={busy || !eSummary.trim()}>
            Add event
          </button>
        </div>
        <div class="scroll">
          <table>
            <thead>
              <tr><th>Time</th><th>Kind</th><th>Source</th><th>Summary</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {#if events.length === 0}
                <tr class="none"><td colspan="5">No timeline events yet.</td></tr>
              {/if}
              {#each events as ev, i (i)}
                <tr>
                  <td class="mono">{when(ev.time)}</td>
                  <td>{ev.kind}</td>
                  <td class="dim">{ev.source || "—"}</td>
                  <td>{ev.summary}</td>
                  <td class="mono">{ev.evidenceId || "—"}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {:else}
      <p class="empty">
        No case open. Name it, or open an existing case file — a case records
        what you examined, what it hashed to, and what you concluded, and is
        exported as a standalone report.
      </p>
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
    width: min(1120px, 96vw);
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

  h2 {
    margin: 0;
    font-size: 18px;
    letter-spacing: 0.02em;
  }

  .meta {
    margin: 0 0 10px;
    font-size: 12.5px;
    color: var(--text);
  }

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
  }

  .options,
  .bar {
    display: flex;
    align-items: center;
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
    min-width: 220px;
  }

  .field.full {
    margin-bottom: 10px;
  }

  .field input,
  .field select,
  .tabs select {
    padding: 4px 6px;
    font-size: 12.5px;
    background: var(--bg-input, transparent);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
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

  .empty {
    margin: 14px 0;
    color: var(--text-dim);
    line-height: 1.6;
    font-size: 13px;
  }

  .scroll {
    overflow: auto;
    max-height: 46vh;
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

  td {
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    vertical-align: top;
  }

  td.url {
    max-width: 40ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  td.hash {
    white-space: normal;
    word-break: break-all;
  }

  tr.none td {
    color: var(--text-dim);
    font-style: italic;
    white-space: normal;
    padding: 14px 8px;
  }

  .verdict {
    margin-left: 6px;
    color: #3f9d63;
    font-weight: 600;
  }

  .verdict.bad {
    color: var(--error, #e06c75);
  }

  .sev {
    display: inline-block;
    padding: 1px 7px;
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-dim);
  }

  .sev-high,
  .sev-critical {
    border-color: #b3341f;
    color: #b3341f;
  }

  .sev-medium {
    border-color: #b8791b;
    color: #b8791b;
  }

  .error {
    margin: 10px 0 0;
    color: var(--error, #e06c75);
    font-size: 12.5px;
  }
</style>
