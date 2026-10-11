<script lang="ts">
  import { store, flash } from "../state.svelte";
  import * as A from "../actions";
  import { svc } from "../api";
  import type { Preferences } from "../../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

  let draft = $state<Preferences | null>(null);
  let defaults = $state<Record<string, string> | null>(null);
  let defaultsError = $state("");
  let defaultsLoading = $state(false);

  // Module-level cache: survives dialog remounts so a transient service
  // failure is retried on the next open/click instead of sticking forever.
  let defaultsCache: Record<string, string> | null = null;
  let defaultsInflight: Promise<Record<string, string> | null> | null = null;

  async function loadDefaults(): Promise<Record<string, string> | null> {
    if (defaultsCache) return defaultsCache;
    if (defaultsInflight) return defaultsInflight;
    defaultsLoading = true;
    defaultsError = "";
    defaultsInflight = (async () => {
      try {
        const d = ((await svc.ShortcutDefaults()) ?? {}) as Record<string, string>;
        if (Object.keys(d).length === 0) {
          throw new Error("stock keymap is empty");
        }
        defaultsCache = d;
        defaults = d;
        return d;
      } catch (e) {
        defaultsError = `Could not load stock shortcuts — click Reset to retry. (${e instanceof Error ? e.message : String(e)})`;
        return null;
      } finally {
        defaultsLoading = false;
        defaultsInflight = null;
      }
    })();
    return defaultsInflight;
  }

  $effect(() => {
    if (store.showPrefs && store.prefs && !draft) {
      draft = structuredClone($state.snapshot(store.prefs));
      if (!draft.shortcuts) draft.shortcuts = {};
    }
    if (!store.showPrefs) draft = null;
  });

  $effect(() => {
    // Reactive deps: store.showPrefs, defaultsCache. defaultsInflight is a
    // plain (non-reactive) guard, so a failed load does not re-trigger the
    // effect in a retry loop — Reset clicks retry explicitly.
    if (store.showPrefs && !defaultsCache && !defaultsInflight) void loadDefaults();
  });

  const profiles: Record<string, string> = {
    analyst: "Analyst — edit documents, save to new files",
    recovery: "Recovery — aggressive recovery-oriented edits",
    readonly: "Read-Only — all modifications rejected",
    examiner: "Examiner — includes guarded physical-disk writes",
  };

  const actionLabels: Record<string, string> = {
    "file.open": "Open file",
    "file.new": "New document",
    "file.save": "Save",
    "file.saveAs": "Save As",
    "file.exportView": "Export view",
    "edit.undo": "Undo",
    "edit.redo": "Redo",
    "edit.cut": "Cut",
    "edit.copy": "Copy (hex)",
    "edit.copyText": "Copy (text)",
    "edit.paste": "Paste",
    "edit.insert": "Insert bytes",
    "edit.fill": "Fill selection",
    "edit.selectAll": "Select all",
    "search.find": "Find",
    "search.replace": "Replace",
    "search.next": "Find next",
    "search.prev": "Find previous",
    "goto.offset": "Goto offset",
    "view.theme": "Cycle theme",
    "preferences.open": "Preferences",
    "help.shortcuts": "Shortcuts help",
  };

  let actions = $derived(Object.keys(actionLabels).sort());

  function chord(action: string): string {
    return draft?.shortcuts?.[action] ?? "";
  }

  function setChord(action: string, value: string): void {
    if (!draft) return;
    if (!draft.shortcuts) draft.shortcuts = {};
    draft.shortcuts[action] = value;
    draft = draft; // trigger rune reactivity on the nested map
  }

  async function resetShortcuts(): Promise<void> {
    if (!draft) return;
    const d = await loadDefaults();
    if (!d) return; // loadDefaults already surfaced defaultsError
    draft.shortcuts = { ...d };
    draft = draft;
    flash("Shortcuts reset to defaults — click Save to apply");
  }

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

      <div class="shortcuts-head">
        <h3>Keyboard shortcuts</h3>
        <button onclick={resetShortcuts} disabled={!draft}>
          {defaultsLoading ? "Loading…" : "Reset to defaults"}
        </button>
      </div>
      {#if defaultsError}
        <p class="error-wide">{defaultsError}</p>
      {/if}
      <p class="hint-wide">
        Chords are <span class="mono">Ctrl+Alt+Shift+Key</span> (aliases Control/Cmd/Option
        accepted). Leave a field empty to unbind. Invalid or duplicate chords are
        rejected on save.
      </p>
      <table class="shortcuts">
        <tbody>
          {#each actions as action}
            <tr>
              <td>{actionLabels[action]}</td>
              <td class="mono dim">{action}</td>
              <td>
                <input
                  class="mono chord"
                  value={chord(action)}
                  placeholder="(unbound)"
                  onchange={(e) => setChord(action, (e.target as HTMLInputElement).value)}
                />
              </td>
            </tr>
          {/each}
        </tbody>
      </table>

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
    max-height: 88vh;
    overflow: auto;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }

  h2 {
    margin: 0 0 16px;
    font-size: 16px;
  }

  h3 {
    margin: 0;
    font-size: 13px;
    letter-spacing: 0.02em;
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

  .hint-wide {
    margin: 4px 0 10px;
    color: var(--text-dim);
    font-size: 11.5px;
    line-height: 1.45;
  }

  .error-wide {
    margin: 4px 0 10px;
    color: var(--err, #e5484d);
    font-size: 11.5px;
    line-height: 1.45;
  }

  .mono {
    font-family: var(--font-mono);
  }

  .dim {
    color: var(--text-dim);
    font-size: 11.5px;
  }

  .chk {
    display: flex;
    gap: 8px;
    align-items: center;
    color: var(--text);
  }

  .shortcuts-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-top: 18px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
  }

  table.shortcuts {
    border-collapse: collapse;
    width: 100%;
    font-size: 12.5px;
    margin-bottom: 6px;
  }

  table.shortcuts td {
    padding: 3px 6px;
    border-bottom: 1px solid var(--border);
  }

  input.chord {
    width: 18ch;
    padding: 3px 6px;
    font-size: 12.5px;
    background: var(--bg-input, transparent);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 18px;
  }
</style>
