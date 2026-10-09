<script lang="ts">
  import { store } from "../state.svelte";
  import { svc, errMsg } from "../api";
  import type {
    Result,
  } from "../../../bindings/github.com/IshikawaUta/gohex/internal/update/models";

  let ver = $state("");
  let updateRes = $state<Result | null>(null);
  let checking = $state(false);
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
