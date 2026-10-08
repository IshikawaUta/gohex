<script lang="ts">
  import { store } from "../state.svelte";
  import { acceptEthics } from "../ethics";

  let { onaccept }: { onaccept: () => void } = $props();

  function accept(): void {
    acceptEthics();
    store.showEthics = false;
    onaccept();
  }
</script>

<div class="overlay" role="dialog" aria-modal="true" aria-label={store.t("dialog.ethics.title")}>
  <div class="modal">
    <h2>⚠ {store.t("dialog.ethics.title")}</h2>
    <p class="body">{store.t("dialog.ethics.browser")}</p>
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

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 18px;
  }
</style>
