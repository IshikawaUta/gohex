<script lang="ts">
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, errMsg } from "../api";

  let members = $state<string[]>([]);
  let missing = $state<boolean[]>([]);
  let level = $state("5");
  let stripe = $state(65536);
  let busy = $state(false);
  let error = $state("");

  $effect(() => {
    if (!store.showRaid) {
      error = "";
    }
  });

  async function addMember(): Promise<void> {
    try {
      const res = await Dialogs.OpenFile({
        Title: "Add RAID member",
        AllowsMultipleSelection: true,
      });
      for (const p of Array.isArray(res) ? res : [res]) {
        if (p && !members.includes(p as string)) {
          members = [...members, p as string];
          missing = [...missing, false];
        }
      }
    } catch (e) {
      error = `Open dialog failed: ${errMsg(e)}`;
    }
  }

  function removeMember(i: number): void {
    members = members.filter((_, j) => j !== i);
    missing = missing.filter((_, j) => j !== i);
  }

  async function openRaid(): Promise<void> {
    if (members.length < 2) return;
    busy = true;
    error = "";
    try {
      const ids = missing.flatMap((m, i) => (m ? [i] : []));
      await svc.RaidOpen(members, level, stripe, ids);
      flash(`RAID ${level} volume opened read-only (${members.length} members)`);
      store.showRaid = false;
      members = [];
      missing = [];
    } catch (e) {
      error = errMsg(e);
    } finally {
      busy = false;
    }
  }

  function fmtName(p: string): string {
    const parts = p.split("/");
    return parts[parts.length - 1] || p;
  }
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Open RAID array"
  tabindex="-1"
  onclick={(e) => {
    if (e.target === e.currentTarget) store.showRaid = false;
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") store.showRaid = false;
  }}
>
  <div class="modal" role="document">
    <div class="head">
      <h2>Open RAID array (read-only)</h2>
      <button class="ghost" onclick={() => (store.showRaid = false)}>Close</button>
    </div>
    <p class="meta">
      Assembles member disk files into a logical volume. RAID 5 rebuilds
      from single failures via XOR parity; RAID 6 adds Reed-Solomon Q
      parity and survives two. Nothing is ever written to a member.
      Parity placement is fixed: last member = P, second-to-last = Q.
    </p>

    <div class="bar">
      <label class="field"><span>Level</span>
        <select bind:value={level}>
          <option value="0">RAID 0 (striping)</option>
          <option value="1">RAID 1 (mirroring)</option>
          <option value="5">RAID 5 (XOR parity)</option>
          <option value="6">RAID 6 (RS double parity)</option>
        </select>
      </label>
      <label class="field"><span>Stripe (bytes)</span>
        <input type="number" bind:value={stripe} min="512" step="512" />
      </label>
      <button onclick={() => void addMember()}>Add member files…</button>
    </div>

    {#if members.length > 0}
      <table>
        <thead>
          <tr><th>#</th><th>File</th><th>Missing?</th><th></th></tr>
        </thead>
        <tbody>
          {#each members as m, i (m)}
            <tr>
              <td>{i}</td>
              <td class="mono" title={m}>{fmtName(m)}</td>
              <td>
                <input
                  type="checkbox"
                  bind:checked={missing[i]}
                  title="Simulate a failed member — reads reconstruct from parity"
                />
              </td>
              <td><button class="ghost" onclick={() => removeMember(i)}>✕</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="empty">No members yet — add the member files in array order.</p>
    {/if}

    <div class="bar" style="justify-content: flex-end;">
      <button class="primary" onclick={() => void openRaid()} disabled={busy || members.length < 2}>
        {busy ? "Opening…" : `Open RAID ${level} volume`}
      </button>
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
    width: min(720px, 96vw);
    max-height: 80vh;
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
  .mono {
    font-family: var(--font-mono);
    font-size: 12px;
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .empty {
    color: var(--text-dim);
    font-size: 13px;
    text-align: center;
    padding: 20px 0;
  }
  .error {
    color: var(--error, #e5534b);
    margin-top: 8px;
  }
  .ghost {
    background: none;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-bottom: 10px;
  }
  th,
  td {
    text-align: left;
    padding: 5px 8px;
    border-bottom: 1px solid var(--border);
  }
</style>
