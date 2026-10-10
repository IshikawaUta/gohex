<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";
  import type {
    Result,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/update/models";

  let ver = $state("");
  let updateRes = $state<Result | null>(null);
  let checking = $state(false);
  let assetURL = $state("");
  let assetSHA = $state("");
  let downloading = $state(false);
  svc.Version().then((v) => (ver = v));

  async function checkUpdate(): Promise<void> {
    checking = true;
    updateRes = null;
    try {
      updateRes = await svc.UpdateCheck();
    } catch (e) {
      updateRes = { current: ver, available: false, error: errMsg(e) };
    } finally {
      checking = false;
    }
  }

  async function downloadUpdate(): Promise<void> {
    if (!assetURL.trim() || !/^[0-9a-fA-F]{64}$/.test(assetSHA.trim())) {
      flash("Paste the release asset URL and its published SHA-256 first.");
      return;
    }
    let dst: string;
    try {
      const res = await Dialogs.SaveFile({
        Title: "Save verified update asset",
        Filename: assetURL.split("/").pop() || "gohex-update.bin",
      });
      dst = (Array.isArray(res) ? res[0] : res) as string;
    } catch (e) {
      flash(`Save dialog failed: ${errMsg(e)}`);
      return;
    }
    if (!dst) return;
    downloading = true;
    try {
      const r = await svc.UpdateDownload(assetURL.trim(), assetSHA.trim(), dst);
      flash(`Verified update saved: ${r.bytes} bytes → ${r.path} (sha256:${r.sha256}). Install it manually.`);
    } catch (e) {
      flash(errMsg(e));
    } finally {
      downloading = false;
    }
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="About GoHex"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showAbout = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showAbout = false;
  }}
>
  <div class="modal" role="document">
    <h2>GoHex</h2>
    <p class="sub">{store.t("app.title")}</p>
    <table><tbody>
      <tr><td>Version</td><td>{ver}</td></tr>
      <tr><td>License</td><td>Apache License 2.0</td></tr>
      <tr><td>Engine</td><td>Go + Wails v3 + Svelte 5</td></tr>
      <tr><td>Telemetry</td><td>None — fully offline</td></tr>
    </tbody></table>

    {#if updateRes}
      <p class="update" class:ok={updateRes.available} class:muted={!updateRes.available}>
        {#if updateRes.error}
          {updateRes.error}
        {:else if updateRes.available}
          Update available: {updateRes.latest} — {updateRes.url ?? ""}
        {:else}
          You are up to date ({updateRes.latest ?? updateRes.current}).
        {/if}
      </p>
    {/if}

    {#if updateRes?.available}
      <div class="dl">
        <p class="disc">
          Downloads are never automatic. Paste the asset URL and the SHA-256
          published with the release; GoHex verifies the digest before the file
          is kept, and never executes it — installing stays your call.
        </p>
        <input
          class="mono"
          bind:value={assetURL}
          placeholder="https://…/gohex_linux_amd64.tar.gz"
          aria-label="Release asset URL"
        />
        <input
          class="mono"
          bind:value={assetSHA}
          placeholder="sha256 hex (64 chars)"
          aria-label="Expected SHA-256"
        />
        <button onclick={() => void downloadUpdate()} disabled={downloading}>
          {downloading ? "Downloading…" : "Download & verify…"}
        </button>
      </div>
    {/if}

    <p class="disc">{store.t("dialog.disclaimer.body")}</p>
    <div class="actions">
      <button onclick={() => void checkUpdate()} disabled={checking}>
        {checking ? "Checking…" : "Check for updates"}
      </button>
      <button class="primary" onclick={() => (store.showAbout = false)}>Close</button>
    </div>
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
    width: min(520px, 92vw);
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px 26px;
  }

  h2 {
    margin: 0;
    font-size: 20px;
    letter-spacing: 0.02em;
  }

  .sub {
    margin: 4px 0 14px;
    color: var(--text-dim);
    font-size: 12.5px;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    font-size: 12.5px;
  }

  td {
    padding: 4px 8px;
    border-bottom: 1px solid var(--border);
  }

  td:first-child {
    color: var(--text-dim);
    width: 110px;
  }

  .update {
    margin: 10px 0 0;
    font-size: 12px;
    color: var(--text-dim);
    word-break: break-all;
  }

  .update.ok {
    color: var(--accent);
  }

  .dl {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 10px;
  }

  .dl input {
    width: 100%;
    font-size: 12px;
    padding: 6px 8px;
    background: var(--bg-app, #111);
    color: var(--text, #eee);
    border: 1px solid var(--border);
    border-radius: 6px;
  }

  .disc {
    font-size: 11.5px;
    color: var(--text-dim);
    line-height: 1.5;
    margin-top: 14px;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 14px;
  }
</style>
