<script lang="ts">
  import { store } from "../state.svelte";
  import * as A from "../actions";
  import type { Preferences } from "../../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

  let draft = $state<Preferences | null>(null);

  $effect(() => {
    if (store.showPrefs && store.prefs && !draft) {
      draft = structuredClone(store.prefs);
    }
    if (!store.showPrefs) draft = null;
  });

  const profiles: Record<string, string> = {
    analyst: "Analyst — edit documents, save to new files",
    recovery: "Recovery — aggressive recovery-oriented edits",
    readonly: "Read-Only — all modifications rejected",
    examiner: "Examiner — includes guarded physical-disk writes",
  };

  async function save(): Promise<void> {
    if (!draft) return;
    await A.preferencesChanged(draft);
    store.showPrefs = false;
    draft = null;
  }
</script>

{#if store.showPrefs && draft}
  <div
    class="overlay"
    role="dialog"
    aria-modal="true"
    aria-label="Preferences"
    tabindex="-1"
    onclick={(e) => {
      if (e.target === e.currentTarget) store.showPrefs = false;
    }}
    onkeydown={(e) => {
      if (e.key === "Escape") store.showPrefs = false;
    }}
  >
    <div class="modal" role="document">
      <h2>⚙ Preferences</h2>

      <div class="grid">
        <label for="pref-theme">{store.t("menu.view.theme")}</label>
        <select id="pref-theme" bind:value={draft.theme}>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
          <option value="high-contrast">High contrast</option>
        </select>

        <label for="pref-lang">Language</label>
        <select id="pref-lang" bind:value={draft.language}>
          <option value="en">English</option>
          <option value="id">Bahasa Indonesia</option>
        </select>

        <label for="pref-bpl">{store.t("menu.view.columns")}</label>
        <select id="pref-bpl" bind:value={draft.bytesPerLine} >
          <option value={8}>8</option>
          <option value={16}>16</option>
          <option value={32}>32</option>
        </select>

        <label for="pref-radix">Offset radix</label>
        <select id="pref-radix" bind:value={draft.offsetRadix}>
          <option value="hex">Hexadecimal</option>
          <option value="dec">Decimal</option>
        </select>

        <label for="pref-profile">Profile</label>
        <select id="pref-profile" bind:value={draft.profile}>
          {#each Object.entries(profiles) as [k, v]}
            <option value={k}>{k}</option>
          {/each}
        </select>
        <div class="hint">{profiles[draft.profile] ?? ""}</div>

        <label for="pref-sandbox">Sandbox mode</label>
        <label class="chk">
          <input id="pref-sandbox" type="checkbox" bind:checked={draft.sandboxMode} />
          Simulate saves without touching the disk
        </label>
        <div class="hint"></div>
      </div>

      <div class="actions">
        <button onclick={() => (store.showPrefs = false)}>Cancel</button>
        <button class="primary" onclick={save}>Save</button>
      </div>
    </div>
  </div>
{/if}

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
    width: min(560px, 94vw);
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }

  h2 {
    margin: 0 0 16px;
    font-size: 16px;
  }

  .grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 10px 14px;
    align-items: center;
    font-size: 13px;
  }

  .grid > label {
    color: var(--text-dim);
    text-align: right;
  }

  .hint {
    grid-column: 2;
    color: var(--text-dim);
    font-size: 11.5px;
    margin-top: -6px;
  }

  .chk {
    display: flex;
    gap: 8px;
    align-items: center;
    color: var(--text);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 18px;
  }
</style>
