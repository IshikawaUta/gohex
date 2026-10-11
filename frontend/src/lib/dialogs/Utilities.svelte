<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg, fromBase64 } from "../api";
  import type { ByteCount } from "../../../bindings/github.com/IshikawaUta/gohex/internal/util/models";
  import type { SearchMatch } from "../../../bindings/github.com/IshikawaUta/gohex/internal/util/models";

  type Tab = "entropy" | "calc" | "regex" | "strings" | "split" | "shred" | "gen" | "time" | "convert";

  let tab = $state<Tab>("entropy");
  let busy = $state(false);
  let error = $state("");
  let result = $state("");

  // Entropy / freq / regex / strings all take a path.
  let path = $state("");
  let topN = $state(16);
  let minLen = $state(4);
  let limit = $state(200);
  let pattern = $state("");
  let entropy = $state<number | null>(null);
  let freq = $state<ByteCount[]>([]);
  let matches = $state<SearchMatch[]>([]);

  // Calc.
  let expr = $state("");
  let calc = $state<Record<string, string | undefined> | null>(null);

  // Split / join / shred.
  let pieceSize = $state(1048576);
  let passes = $state(3);
  let shredPath = $state("");
  let splitSrc = $state("");
  let joinDst = $state("");
  let parts = $state<string[]>([]);

  // Generators.
  let pwLen = $state(20);
  let rndLen = $state(16);
  let generated = $state("");

  // Timestamp.
  let epoch = $state(0);
  let unit = $state("s");
  let ts = $state<Record<string, string | undefined> | null>(null);

  // PNG export.
  let pngOffset = $state(0);
  let pngLength = $state(256);
  let pngScale = $state(4);

  // Convert (text↔hex, Intel HEX, S-records).
  let convMode = $state<"t2h" | "h2t" | "ihex" | "srec">("t2h");
  let convEnc = $state("UTF-8");
  let convIn = $state("");
  let convOut = $state("");
  let convNote = $state("");

  $effect(() => {
    if (!store.showUtilities) {
      error = "";
      result = "";
    }
  });

  async function pickFile(target: (p: string) => void): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({ Title: "Pick a file" });
      const p = (Array.isArray(res) ? res[0] : res) as string;
      if (p) target(p);
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  async function runEntropy(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    try {
      const g = await svc.EntropyOf(path);
      entropy = g?.["entropy"] ?? null;
      freq = (await svc.ByteFreq(path, topN)) ?? [];
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function runCalc(): Promise<void> {
    busy = true;
    error = "";
    try {
      calc = (await svc.HexCalc(expr)) ?? null;
    } catch (e) {
      error = errMsg(e);
      calc = null;
    } finally {
      busy = false;
    }
  }

  async function runRegex(): Promise<void> {
    if (!path || !pattern) return;
    busy = true;
    error = "";
    try {
      matches = (await svc.RegexTest(path, pattern, limit)) ?? [];
    } catch (e) {
      error = errMsg(e);
      matches = [];
    } finally {
      busy = false;
    }
  }

  async function runStrings(): Promise<void> {
    if (!path) return;
    busy = true;
    error = "";
    try {
      matches = (await svc.StringsOf(path, minLen, limit)) ?? [];
    } catch (e) {
      error = errMsg(e);
      matches = [];
    } finally {
      busy = false;
    }
  }

  async function runSplit(): Promise<void> {
    if (!splitSrc) return;
    let dstPattern: string;
    try {
      const res = await Dialogs.SaveFile({ Title: "Destination pattern (%d → part name)", Filename: "part-%d.bin" });
      dstPattern = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dstPattern) return;
    // The dialog returns a concrete name; force a %d placeholder in.
    if (!dstPattern.includes("%d")) dstPattern = dstPattern.replace(/(\.[^.]+)$/, "-%d$1");
    if (!dstPattern.includes("%d")) dstPattern += "-%d";
    busy = true;
    error = "";
    try {
      parts = (await svc.SplitFile(splitSrc, dstPattern, pieceSize)) ?? [];
      flash(`Split into ${parts.length} pieces`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function runJoin(): Promise<void> {
    if (parts.length === 0) return;
    let dst: string;
    try {
      const res = await Dialogs.SaveFile({ Title: "Join into", Filename: "joined.bin" });
      dst = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const n = await svc.JoinFiles(parts, dst);
      flash(`Joined ${parts.length} parts → ${dst} (${n} bytes)`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function runShred(): Promise<void> {
    if (!shredPath) return;
    if (!confirm("Shred permanently overwrites the file. On SSD/CoW filesystems this is best-effort only. Continue?")) return;
    busy = true;
    error = "";
    try {
      await svc.Shred(shredPath, passes);
      flash(`Shredded ${shredPath} (${passes} passes, best-effort)`);
      shredPath = "";
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function gen(kind: "pw" | "uuid" | "ulid" | "rand"): Promise<void> {
    busy = true;
    error = "";
    try {
      switch (kind) {
        case "pw":
          generated = await svc.PasswordGen(pwLen);
          break;
        case "uuid":
          generated = await svc.UUIDGen();
          break;
        case "ulid":
          generated = await svc.ULIDGen();
          break;
        case "rand":
          generated = await svc.RandomHex(rndLen);
          break;
      }
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function runTime(): Promise<void> {
    busy = true;
    error = "";
    try {
      ts = (await svc.TimestampConvert(epoch, unit)) ?? null;
    } catch (e) {
      error = errMsg(e);
      ts = null;
    } finally {
      busy = false;
    }
  }

  async function runConvert(): Promise<void> {
    busy = true;
    error = "";
    convOut = "";
    convNote = "";
    try {
      if (convMode === "t2h") {
        convOut = (await svc.ConvertTextToHex(convIn, convEnc)) ?? "";
        convNote = `${convIn.length} character(s) → hex`;
      } else if (convMode === "h2t") {
        convOut = (await svc.ConvertHexToText(convIn, convEnc)) ?? "";
        convNote = `${convIn.replace(/\s+/g, "").length / 2} byte(s) → text`;
      } else {
        const [b64, origin] = (convMode === "ihex"
          ? await svc.ConvertIntelHex(convIn)
          : await svc.ConvertSRecords(convIn)) as [string | null, number];
        const len = b64 ? Math.floor((b64.length * 3) / 4) : 0;
        convNote = `${len} byte(s), origin 0x${origin.toString(16).toUpperCase()}`;
        convOut = b64
          ? Array.from(fromBase64(b64).subarray(0, 512))
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ") + (len > 512 ? " …" : "")
          : "";
      }
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  async function exportPNG(): Promise<void> {
    const doc = store.active;
    if (!doc) return;
    let dst: string;
    try {
      const res = await Dialogs.SaveFile({ Title: "Export hex view as PNG", Filename: `${doc.name}.png` });
      dst = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      error = `Save dialog failed: ${errMsg(e)}`;
      return;
    }
    if (!dst) return;
    busy = true;
    error = "";
    try {
      const r = await svc.ExportPNG(doc.id, pngOffset, pngLength, pngScale, dst);
      flash(`PNG exported: ${r.bytesSaved} bytes → ${r.path}`);
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function fmt(v: string | undefined): string {
    return v ?? "—";
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Utilities"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showUtilities = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showUtilities = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Utilities</h2>
      <button class="ghost" onclick={() => (store.showUtilities = false)}>Close</button>
    </div>
    <p class="meta">
      Entropy, byte frequency, hex calculator, regex tester, strings,
      split/join, secure delete (best-effort), password/UUID/ULID/RNG,
      timestamp converter, converters (text/hex/Intel HEX/S-records)
      and hex-view PNG export.
    </p>

    <div class="tabs" role="tablist">
      {#each [["entropy", "Entropy"], ["calc", "Calculator"], ["regex", "Regex"], ["strings", "Strings"], ["split", "Split/Join"], ["shred", "Shred"], ["gen", "Generators"], ["time", "Timestamp"], ["convert", "Convert"]] as [id, label]}
        <button role="tab" class:active={tab === id} aria-selected={tab === id} onclick={() => (tab = id as Tab)}>{label}</button>
      {/each}
    </div>

    {#if tab === "entropy"}
      <div class="bar">
        <label class="field grow"><span>File</span>
          <input bind:value={path} placeholder="/path/to/file" />
        </label>
        <button onclick={() => void pickFile((p) => (path = p))}>Browse…</button>
        <label class="field"><span>Top bytes</span><input type="number" bind:value={topN} min="1" max="256" /></label>
        <button class="primary" onclick={() => void runEntropy()} disabled={busy || !path}>Analyze</button>
      </div>
      {#if entropy !== null}
        <p>Shannon entropy: <strong>{entropy.toFixed(4)}</strong> bits/byte</p>
        <table>
          <thead><tr><th>Byte</th><th>Hex</th><th>Count</th></tr></thead>
          <tbody>
            {#each freq as f (f.byte)}
              <tr><td class="mono">{f.byte}</td><td class="mono">0x{f.byte.toString(16).padStart(2, "0").toUpperCase()}</td><td class="mono">{f.count}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {:else if tab === "calc"}
      <div class="bar">
        <label class="field grow"><span>Expression</span>
          <input bind:value={expr} placeholder="0x1000 + 256 * 4" onkeydown={(e) => e.key === "Enter" && void runCalc()} />
        </label>
        <button class="primary" onclick={() => void runCalc()} disabled={busy || !expr.trim()}>Evaluate</button>
      </div>
      {#if calc}
        <dl>
          <dt>Decimal</dt><dd class="mono">{fmt(calc["dec"])}</dd>
          <dt>Hex (upper)</dt><dd class="mono">{fmt(calc["hex"])}</dd>
          <dt>Hex (lower)</dt><dd class="mono">{fmt(calc["hexlow"])}</dd>
          <dt>Octal</dt><dd class="mono">{fmt(calc["oct"])}</dd>
          <dt>Binary</dt><dd class="mono">{fmt(calc["bin"])}</dd>
          <dt>Min bytes</dt><dd class="mono">{fmt(calc["bytes"])}</dd>
        </dl>
      {/if}
    {:else if tab === "regex"}
      <div class="bar">
        <label class="field grow"><span>File</span><input bind:value={path} placeholder="/path/to/file" /></label>
        <button onclick={() => void pickFile((p) => (path = p))}>Browse…</button>
      </div>
      <div class="bar">
        <label class="field grow"><span>Pattern</span><input bind:value={pattern} placeholder="\\x89PNG" onkeydown={(e) => e.key === "Enter" && void runRegex()} /></label>
        <label class="field"><span>Limit</span><input type="number" bind:value={limit} min="1" max="10000" /></label>
        <button class="primary" onclick={() => void runRegex()} disabled={busy || !path || !pattern}>Search</button>
      </div>
      {#if matches.length > 0}
        <p>{matches.length} match(es)</p>
        <table>
          <thead><tr><th>Offset</th><th>Length</th><th>Text</th></tr></thead>
          <tbody>
            {#each matches as m (m.offset)}
              <tr><td class="mono">0x{m.offset.toString(16).toUpperCase()}</td><td class="mono">{m.length}</td><td class="mono">{m.text}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {:else if tab === "strings"}
      <div class="bar">
        <label class="field grow"><span>File</span><input bind:value={path} placeholder="/path/to/file" /></label>
        <button onclick={() => void pickFile((p) => (path = p))}>Browse…</button>
      </div>
      <div class="bar">
        <label class="field"><span>Min length</span><input type="number" bind:value={minLen} min="1" max="64" /></label>
        <label class="field"><span>Limit</span><input type="number" bind:value={limit} min="1" max="10000" /></label>
        <button class="primary" onclick={() => void runStrings()} disabled={busy || !path}>Extract</button>
      </div>
      {#if matches.length > 0}
        <p>{matches.length} string(s)</p>
        <table>
          <thead><tr><th>Offset</th><th>Length</th><th>Text</th></tr></thead>
          <tbody>
            {#each matches as m (m.offset)}
              <tr><td class="mono">0x{m.offset.toString(16).toUpperCase()}</td><td class="mono">{m.length}</td><td class="mono">{m.text}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {:else if tab === "split"}
      <div class="bar">
        <label class="field grow"><span>Source</span><input bind:value={splitSrc} placeholder="/path/to/source" /></label>
        <button onclick={() => void pickFile((p) => (splitSrc = p))}>Browse…</button>
      </div>
      <div class="bar">
        <label class="field"><span>Piece size (bytes)</span><input type="number" bind:value={pieceSize} min="1" /></label>
        <button class="primary" onclick={() => void runSplit()} disabled={busy || !splitSrc}>Split…</button>
      </div>
      {#if parts.length > 0}
        <p>Wrote {parts.length} piece(s):</p>
        <ul>
          {#each parts as p (p)}
            <li class="mono">{p}</li>
          {/each}
        </ul>
        <div class="bar">
          <label class="field grow"><span>Join into</span><input bind:value={joinDst} placeholder="/path/to/joined.bin" /></label>
          <button class="primary" onclick={() => void runJoin()} disabled={busy || parts.length === 0}>Join…</button>
        </div>
      {/if}
    {:else if tab === "shred"}
      <div class="bar">
        <label class="field grow"><span>File</span><input bind:value={shredPath} placeholder="/path/to/secret" /></label>
        <button onclick={() => void pickFile((p) => (shredPath = p))}>Browse…</button>
      </div>
      <div class="bar">
        <label class="field"><span>Passes</span><input type="number" bind:value={passes} min="1" max="35" /></label>
        <button class="danger" onclick={() => void runShred()} disabled={busy || !shredPath}>Shred permanently…</button>
      </div>
      <p class="warn">
        Best-effort only: on SSD, CoW (btrfs/APFS), journaled or
        virtualised filesystems the original bytes may survive in
        unallocated extents. Treat the result as a hint, not a guarantee.
      </p>
    {:else if tab === "gen"}
      <div class="bar">
        <label class="field"><span>Password length</span><input type="number" bind:value={pwLen} min="1" max="256" /></label>
        <button onclick={() => void gen("pw")} disabled={busy}>Password</button>
      </div>
      <div class="bar">
        <button onclick={() => void gen("uuid")} disabled={busy}>UUID v4</button>
        <button onclick={() => void gen("ulid")} disabled={busy}>ULID</button>
        <label class="field"><span>Random bytes</span><input type="number" bind:value={rndLen} min="1" max="4096" /></label>
        <button onclick={() => void gen("rand")} disabled={busy}>Random hex</button>
      </div>
      {#if generated}
        <p class="mono result">{generated}</p>
        <button onclick={() => void navigator.clipboard.writeText(generated)}>Copy</button>
      {/if}
    {:else if tab === "time"}
      <div class="bar">
        <label class="field grow"><span>Epoch value</span><input type="number" bind:value={epoch} onkeydown={(e) => e.key === "Enter" && void runTime()} /></label>
        <label class="field"><span>Unit</span>
          <select bind:value={unit}>
            <option value="s">seconds</option>
            <option value="ms">milliseconds</option>
            <option value="us">microseconds</option>
            <option value="ns">nanoseconds</option>
          </select>
        </label>
        <button class="primary" onclick={() => void runTime()} disabled={busy}>Convert</button>
      </div>
      {#if ts}
        <dl>
          <dt>UTC</dt><dd class="mono">{fmt(ts["utc"])}</dd>
          <dt>Local</dt><dd class="mono">{fmt(ts["local"])}</dd>
          <dt>ISO-8601</dt><dd class="mono">{fmt(ts["iso8601"])}</dd>
          <dt>RFC 1123</dt><dd class="mono">{fmt(ts["rfc1123"])}</dd>
          <dt>Unix (s)</dt><dd class="mono">{fmt(ts["unix"])}</dd>
          <dt>Unix (ms)</dt><dd class="mono">{fmt(ts["unix_ms"])}</dd>
          <dt>FILETIME</dt><dd class="mono">{fmt(ts["filetime"])}</dd>
          <dt>Kind</dt><dd>{fmt(ts["kind"])}</dd>
        </dl>
      {/if}
      <div class="bar" style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 12px;">
        <span class="lbl">PNG export of active document</span>
        <label class="field"><span>Offset</span><input type="number" bind:value={pngOffset} min="0" /></label>
        <label class="field"><span>Length</span><input type="number" bind:value={pngLength} min="1" /></label>
        <label class="field"><span>Scale</span><input type="number" bind:value={pngScale} min="1" max="16" /></label>
        <button onclick={() => void exportPNG()} disabled={busy || !store.active}>Export PNG…</button>
      </div>
    {:else if tab === "convert"}
      <div class="bar">
        <label class="field"><span>Mode</span>
          <select bind:value={convMode}>
            <option value="t2h">Text → hex</option>
            <option value="h2t">Hex → text</option>
            <option value="ihex">Intel HEX → bytes</option>
            <option value="srec">S-records → bytes</option>
          </select>
        </label>
        {#if convMode === "t2h" || convMode === "h2t"}
          <label class="field"><span>Encoding</span>
            <select bind:value={convEnc}>
              <option>UTF-8</option>
              <option>UTF-16LE</option>
              <option>UTF-16BE</option>
              <option>ASCII</option>
              <option>EBCDIC</option>
            </select>
          </label>
        {/if}
        <button class="primary" onclick={() => void runConvert()} disabled={busy || !convIn}>Convert</button>
      </div>
      <label class="field grow"><span>
        {convMode === "t2h"
          ? "Text"
          : convMode === "h2t"
            ? "Hex bytes (spaces optional)"
            : convMode === "ihex"
              ? "Intel HEX stream (:10000000…)"
              : "S-record stream (S0/S1/S9…)"}
      </span>
        <textarea bind:value={convIn} rows={5} spellcheck="false"></textarea>
      </label>
      {#if convOut}
        <p class="meta">{convNote}</p>
        <textarea class="mono" readonly rows={5} value={convOut}></textarea>
        <button onclick={() => void navigator.clipboard.writeText(convOut)}>Copy result</button>
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
    width: min(980px, 96vw);
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
    margin-bottom: 8px;
  }
  h2 {
    margin: 0;
    font-size: 18px;
  }
  .meta {
    margin: 0 0 12px;
    font-size: 12.5px;
    color: var(--text-dim);
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }
  .tabs button {
    background: none;
    border: 1px solid transparent;
    color: var(--text);
    padding: 5px 12px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12.5px;
  }
  .tabs button.active {
    border-color: var(--accent, #4a9eff);
    background: var(--bg-hover, rgba(127, 127, 127, 0.15));
  }
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
  .mono {
    font-family: var(--font-mono);
  }
  .result {
    background: var(--bg-hover, rgba(127, 127, 127, 0.1));
    padding: 10px 14px;
    border-radius: 6px;
    word-break: break-all;
  }
  .error {
    color: var(--error, #e5534b);
    margin-top: 8px;
  }
  .warn {
    color: var(--warn, #d29922);
    font-size: 12.5px;
  }
  .lbl {
    font-size: 12px;
    color: var(--text-dim);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }
  th,
  td {
    text-align: left;
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }
  .ghost {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 5px 12px;
    border-radius: 6px;
    cursor: pointer;
  }
  .danger {
    background: #a4262c;
    border: none;
    color: #fff;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 16px;
    margin: 0;
  }
  dt {
    color: var(--text-dim);
    font-size: 12.5px;
  }
  dd {
    margin: 0;
    font-size: 12.5px;
  }
  ul {
    margin: 0 0 10px;
    padding-left: 20px;
    font-size: 12.5px;
  }
</style>
