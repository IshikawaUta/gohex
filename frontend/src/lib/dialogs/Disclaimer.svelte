<script lang="ts">
  import { store } from "../state.svelte";
  import { acceptDisclaimer } from "../disclaimer";

  function accept(): void {
    acceptDisclaimer();
    store.showDisclaimer = false;
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={store.t("dialog.disclaimer.title")}>
  <div class="modal">
    <h2>⚠ {store.t("dialog.disclaimer.title")}</h2>
    <p class="body">{store.t("dialog.disclaimer.body")}</p>
    <ul>
      <li>Read-only by default — no disk writes without explicit opt-in.</li>
      <li>All open/save/export actions are recorded in a local audit log.</li>
      <li>No telemetry, no network calls, no cloud processing.</li>
      <li>For authorized examination of systems and data you own.</li>
    </ul>
    <div class="actions">
      <button class="primary" onclick={accept}>I understand — continue</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.62);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .modal {
    width: min(560px, 92vw);
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px 26px;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.5);
  }

  h2 {
    margin: 0 0 12px;
    font-size: 17px;
    color: var(--dirty);
  }

  .body {
    line-height: 1.55;
    color: var(--text);
  }

  ul {
    color: var(--text-dim);
    line-height: 1.7;
    padding-left: 20px;
    font-size: 12.5px;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 16px;
  }
</style>
