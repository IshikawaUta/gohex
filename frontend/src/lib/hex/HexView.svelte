<script lang="ts">
  import { onDestroy } from "svelte";
  import { store, flash } from "../state.svelte";
  import { svc, Dialogs, Clipboard, fromBase64, toBase64, errMsg } from "../api";
  import { hexOffset, offsetDigits, hexBytes } from "../format";

  interface Props {
    docId: number;
    size: number;
    bpl: number;
    enc: string;
    editable: boolean;
    version: number;
  }

  let { docId, size, bpl, enc, editable, version }: Props = $props();

  const ROW_H = 22;
  const CHUNK = 1 << 16;
  const OVERSCAN = 6;
  const CELL_W = 26;
  const GRP_GAP = 10;

  let scrollEl: HTMLElement | undefined = $state();
  let scrollTop = $state(0);
  let viewportH = $state(600);
  let dragging = $state(false);
  let menu = $state<{ x: number; y: number; off: number } | null>(null);

  let anchor = 0;
  let chunks = new Map<number, { bytes: Uint8Array; text: string } | null>();
  let epoch = 0;
  let cacheGen = $state(0);

  const digits = $derived(offsetDigits(size));
  const rowCount = $derived(size <= 0 ? 1 : Math.ceil(size / bpl));
  const totalH = $derived(rowCount * ROW_H);
  const firstRow = $derived(Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN));
  const visibleRows = $derived.by(() => {
    const n = Math.min(rowCount, Math.ceil(viewportH / ROW_H) + OVERSCAN * 2);
    const out: number[] = [];
    for (let i = 0; i < n; i++) out.push(firstRow + i);
    return out;
  });
  const gridWidth = $derived(
    24 + digits * 9 + 18 + bpl * CELL_W + Math.max(0, bpl / 8 - 1) * GRP_GAP + 24 + bpl * 9 + 24,
  );

  const singleByte = $derived(enc === "ASCII" || enc === "EBCDIC");

  const reveal: (off: number, selLen?: number) => void = (off, selLen = 0) => {
    const o = Math.max(0, Math.min(off, Math.max(0, size - 1)));
    anchor = o;
    store.cursor = o;
    store.selStart = o;
    store.selEnd = Math.min(size, o + selLen);
    store.pendingNibble = -1;
    // Move keyboard focus to the grid — but never steal it from a text
    // entry field (find/goto inputs may be mid-typing when a reveal lands).
    const ae = document.activeElement;
    const tag = ae?.tagName;
    if (tag !== "INPUT" && tag !== "TEXTAREA") {
      scrollEl?.focus({ preventScroll: true });
    }
    ensureVisible(o);
    commitSel();
  };
  store.revealFn = reveal;
  store.copyFn = copySelection;
  onDestroy(() => {
    if (store.revealFn === reveal) store.revealFn = null;
    if (store.copyFn === copySelection) store.copyFn = null;
    window.removeEventListener("mousemove", onPointerMove);
  });

  function ensureVisible(off: number): void {
    if (!scrollEl) return;
    const row = Math.floor(off / bpl);
    const top = row * ROW_H;
    const bottom = top + ROW_H;
    if (top < scrollEl.scrollTop) scrollEl.scrollTop = top;
    else if (bottom > scrollEl.scrollTop + viewportH) scrollEl.scrollTop = bottom - viewportH;
  }

  function commitSel(): void {
    void svc.SetSelection(docId, store.selStart, store.selEnd).catch(() => {});
  }

  function ensureRange(start: number, end: number): void {
    if (end <= start || docId <= 0) return;
    const c0 = Math.floor(start / CHUNK);
    const c1 = Math.floor((end - 1) / CHUNK);
    for (let c = c0; c <= c1; c++) {
      if (chunks.has(c)) continue;
      chunks.set(c, null);
      const myEpoch = epoch;
      const off = c * CHUNK;
      svc
        .ReadWindow(docId, off, CHUNK)
        .then((w) => {
          if (myEpoch !== epoch) {
            chunks.delete(c);
            return;
          }
          chunks.set(c, { bytes: fromBase64(w.bytes ?? ""), text: w.text ?? "" });
          cacheGen++;
        })
        .catch(() => {
          if (myEpoch === epoch) chunks.delete(c);
          cacheGen++;
        });
    }
  }

  $effect(() => {
    void version;
    chunks.clear();
    epoch++;
  });

  $effect(() => {
    void version;
    const start = firstRow * bpl;
    const end = Math.min(size, (firstRow + visibleRows.length) * bpl);
    void cacheGen;
    ensureRange(start, end);
  });

  function chunkFor(off: number): { bytes: Uint8Array; text: string } | null | undefined {
    return chunks.get(Math.floor(off / CHUNK));
  }

  function byteAt(off: number): number | null {
    if (off < 0 || off >= size) return null;
    const c = chunkFor(off);
    if (!c) return null;
    const local = off - Math.floor(off / CHUNK) * CHUNK;
    return local < c.bytes.length ? c.bytes[local] : null;
  }

  function textAt(off: number): string {
    const b = byteAt(off);
    if (b === null) return " ";
    if (singleByte) {
      const c = chunkFor(off);
      if (c && c.text.length === c.bytes.length) {
        const local = off - Math.floor(off / CHUNK) * CHUNK;
        const ch = c.text[local];
        if (ch && ch !== "\n" && ch !== "\r") return ch;
      }
    }
    return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }

  function hexAt(off: number): string {
    const b = byteAt(off);
    if (b === null) return off >= size ? "" : "··";
    return b.toString(16).toUpperCase().padStart(2, "0");
  }

  function isSel(off: number): boolean {
    return off >= store.selStart && off < store.selEnd;
  }

  function offFromTarget(t: EventTarget | null): number | null {
    if (!(t instanceof Element)) return null;
    const el = t.closest("[data-off]");
    if (!el) return null;
    const v = Number(el.getAttribute("data-off"));
    return Number.isFinite(v) ? v : null;
  }

  function moveCursor(off: number, extend: boolean): void {
    const o = Math.max(0, Math.min(off, Math.max(0, size - 1)));
    store.pendingNibble = -1;
    if (extend) {
      store.selStart = Math.min(anchor, o);
      store.selEnd = Math.min(size, Math.max(anchor, o) + 1);
    } else {
      anchor = o;
      store.selStart = o;
      store.selEnd = o;
    }
    store.cursor = o;
    ensureVisible(o);
    commitSel();
  }

  function onPointerDown(e: MouseEvent): void {
    if (e.button === 2) {
      const off = offFromTarget(e.target);
      if (off !== null) {
        if (!isSel(off)) moveCursor(off, false);
        menu = { x: e.clientX, y: e.clientY, off };
      }
      return;
    }
    if (e.button !== 0) return;
    scrollEl?.focus({ preventScroll: true });
    menu = null;
    const off = offFromTarget(e.target);
    if (off === null) return;
    e.preventDefault();
    if (e.shiftKey) moveCursor(off, true);
    else moveCursor(off, false);
    dragging = true;
    window.addEventListener("mousemove", onPointerMove);
    window.addEventListener("mouseup", onPointerUp, { once: true });
  }

  function onPointerMove(e: MouseEvent): void {
    if (!dragging) return;
    const off = offFromTarget(document.elementFromPoint(e.clientX, e.clientY));
    if (off === null) return;
    moveCursor(off, true);
  }

  function onPointerUp(): void {
    dragging = false;
    window.removeEventListener("mousemove", onPointerMove);
  }

  function rowsOnScreen(): number {
    return Math.max(1, Math.floor(viewportH / ROW_H) - 2);
  }

  async function copySelection(kind: "hex" | "text" | "offset"): Promise<void> {
    try {
      if (kind === "offset") {
        await Clipboard.SetText(`0x${store.cursor.toString(16).toUpperCase()}`);
        return;
      }
      let start = store.selStart;
      let end = store.selEnd;
      if (end <= start) {
        start = store.cursor;
        end = Math.min(size, start + 1);
      }
      const len = end - start;
      if (len <= 0) return;
      if (len > 16 << 20) {
        flash("Selection too large to copy (max 16 MiB)");
        return;
      }
      const w = await svc.ReadWindow(docId, start, len);
      const bytes = fromBase64(w.bytes ?? "");
      if (kind === "hex") await Clipboard.SetText(hexBytes(bytes));
      else {
        let out = "";
        for (let i = 0; i < bytes.length; i++) {
          const b = bytes[i];
          out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
        }
        await Clipboard.SetText(out);
      }
      flash(`Copied ${len} byte${len === 1 ? "" : "s"}`);
    } catch (e) {
      flash(errMsg(e));
    }
  }

  async function deleteSelection(): Promise<void> {
    menu = null;
    const len = store.selEnd - store.selStart;
    if (len <= 0 || !editable) return;
    const ans = await Dialogs.Question({
      Title: store.t("menu.edit"),
      Message: `Delete ${len} byte${len === 1 ? "" : "s"} at offset 0x${store.selStart.toString(16).toUpperCase()}? This changes the file size.`,
    });
    if (ans !== "Yes") return;
    try {
      await svc.DeleteRange(docId, store.selStart, len);
      flash(`Deleted ${len} bytes (undo with ${navigator.platform.startsWith("Mac") ? "⌘" : "Ctrl"}+Z)`);
    } catch (e) {
      Dialogs.Error({ Title: store.t("error.saveFailed"), Message: errMsg(e) });
    }
  }

  function selectAll(): void {
    menu = null;
    anchor = 0;
    store.cursor = 0;
    store.selStart = 0;
    store.selEnd = size;
    store.pendingNibble = -1;
    commitSel();
  }

  function closeMenu(): void {
    menu = null;
  }

  async function onKeyDown(e: KeyboardEvent): Promise<void> {
    if (!scrollEl || !scrollEl.contains(document.activeElement)) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const key = e.key;
    const rows = rowsOnScreen();

    if (/^[0-9a-fA-F]$/.test(key) && !e.shiftKey) {
      if (!editable || size <= 0) return;
      e.preventDefault();
      const nib = parseInt(key, 16);
      if (store.pendingNibble < 0) {
        store.pendingNibble = nib;
        return;
      }
      const byte = (store.pendingNibble << 4) | nib;
      store.pendingNibble = -1;
      try {
        await svc.WriteBytes(docId, store.cursor, toBase64(Uint8Array.of(byte)));
        moveCursor(Math.min(store.cursor + 1, Math.max(0, size - 1)), false);
      } catch (err) {
        flash(errMsg(err));
      }
      return;
    }

    switch (key) {
      case "ArrowLeft":
        e.preventDefault();
        moveCursor(store.cursor - 1, e.shiftKey);
        break;
      case "ArrowRight":
        e.preventDefault();
        moveCursor(store.cursor + 1, e.shiftKey);
        break;
      case "ArrowUp":
        e.preventDefault();
        moveCursor(store.cursor - bpl, e.shiftKey);
        break;
      case "ArrowDown":
        e.preventDefault();
        moveCursor(store.cursor + bpl, e.shiftKey);
        break;
      case "Home":
        e.preventDefault();
        moveCursor(
          e.ctrlKey ? 0 : Math.floor(store.cursor / bpl) * bpl,
          e.shiftKey,
        );
        break;
      case "End":
        e.preventDefault();
        moveCursor(
          e.ctrlKey
            ? size - 1
            : Math.min(size - 1, Math.floor(store.cursor / bpl) * bpl + bpl - 1),
          e.shiftKey,
        );
        break;
      case "PageUp":
        e.preventDefault();
        moveCursor(store.cursor - rows * bpl, e.shiftKey);
        break;
      case "PageDown":
        e.preventDefault();
        moveCursor(store.cursor + rows * bpl, e.shiftKey);
        break;
      case "Escape":
        store.pendingNibble = -1;
        closeMenu();
        moveCursor(store.cursor, false);
        break;
      case "Backspace":
        if (store.pendingNibble >= 0) {
          e.preventDefault();
          store.pendingNibble = -1;
        }
        break;
      default:
        return;
    }
  }
</script>

<svelte:window onkeydown={onKeyDown} onclick={closeMenu} />

<div
  class="hexview"
  tabindex="0"
  bind:this={scrollEl}
  bind:clientHeight={viewportH}
  onscroll={() => (scrollTop = scrollEl?.scrollTop ?? 0)}
  onmousedown={onPointerDown}
  role="grid"
  aria-label="Hex grid"
>
  <div class="canvas" style="height:{totalH}px; width:{gridWidth}px">
    {#each visibleRows as row (cacheGen + ":" + row)}
      {#if row < rowCount}
        {@const rowOff = row * bpl}
        <div class="row" style="top:{row * ROW_H}px" data-row={row}>
          <span class="off">{hexOffset(rowOff, digits)}</span>
          <span class="hex">
            {#each Array.from({ length: bpl }) as _, col}
              {@const off = rowOff + col}
              {#if off < size}
                <span
                  class="cell{isSel(off) ? " sel" : ""}{off === store.cursor ? " cur" : ""}{col > 0 &&
                  col % 8 === 0
                    ? " grp"
                    : ""}"
                  data-off={off}
                >
                  {#if off === store.cursor && store.pendingNibble >= 0}
                    {store.pendingNibble.toString(16).toUpperCase()}_
                  {:else}{hexAt(off)}{/if}
                </span>
              {:else}
                <span class="cell pad"></span>
              {/if}
            {/each}
          </span>
          <span class="txt">
            {#each Array.from({ length: bpl }) as _, col}
              {@const off = rowOff + col}
              {#if off < size}
                <span
                  class="tch{isSel(off) ? " sel" : ""}{off === store.cursor ? " cur" : ""}"
                  data-off={off}>{textAt(off)}</span
                >
              {:else}
                <span class="tch pad"> </span>
              {/if}
            {/each}
          </span>
        </div>
      {/if}
    {/each}
  </div>

  {#if size === 0}
    <div class="empty-hint">Empty document — type bytes or use Edit ▸ Insert</div>
  {/if}

  {#if menu}
    <div
      class="ctx"
      style="left:{menu.x}px; top:{menu.y}px"
      role="menu"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => {
        if (e.key === "Escape") closeMenu();
      }}
    >
      <button onclick={() => copySelection("offset")}>Copy offset</button>
      <button onclick={() => { copySelection("hex"); closeMenu(); }}>Copy as hex</button>
      <button onclick={() => { copySelection("text"); closeMenu(); }}>Copy as text</button>
      <button onclick={selectAll}>Select all</button>
      {#if editable && store.selEnd > store.selStart}
        <button class="danger" onclick={deleteSelection}>Delete selection</button>
      {/if}
    </div>
  {/if}
</div>

<style>
  .hexview {
    position: relative;
    flex: 1;
    overflow: auto;
    background: var(--bg);
    outline: none;
    font-family: var(--font-mono);
    font-size: 13px;
    line-height: 22px;
  }

  .hexview:focus {
    box-shadow: inset 0 0 0 1px var(--accent);
  }

  .canvas {
    position: relative;
  }

  .row {
    position: absolute;
    left: 0;
    height: var(--row-h);
    display: flex;
    align-items: center;
    white-space: pre;
    padding-left: 8px;
    width: 100%;
  }

  .row:hover {
    background: color-mix(in srgb, var(--accent) 6%, transparent);
  }

  .off {
    color: var(--text-dim);
    padding-right: 14px;
    flex: none;
    opacity: 0.85;
  }

  .hex {
    flex: none;
    display: flex;
  }

  .cell {
    width: 26px;
    text-align: center;
    border-radius: 3px;
    cursor: default;
  }

  .cell.grp {
    margin-left: 10px;
  }

  .cell.pad,
  .tch.pad {
    visibility: hidden;
  }

  .txt {
    flex: none;
    margin-left: 18px;
    padding-left: 14px;
    border-left: 1px solid var(--border);
    display: flex;
    color: var(--text-dim);
  }

  .tch {
    width: 9px;
    text-align: center;
    border-radius: 2px;
  }

  .sel {
    background: var(--sel);
    color: var(--text);
  }

  .cell.cur {
    outline: 1px solid var(--cursor-cell);
    outline-offset: -1px;
    background: var(--accent-soft);
    color: var(--text);
    font-weight: 600;
  }

  .tch.cur {
    outline: 1px solid var(--cursor-cell);
    outline-offset: -1px;
  }

  .empty-hint {
    position: absolute;
    inset: 40% 0 auto 0;
    text-align: center;
    color: var(--text-dim);
    font-family: var(--font-ui);
    pointer-events: none;
  }

  .ctx {
    position: fixed;
    z-index: 60;
    display: flex;
    flex-direction: column;
    min-width: 180px;
    padding: 4px;
    background: var(--bg-panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }

  .ctx button {
    text-align: left;
    border: none;
    background: transparent;
    padding: 6px 10px;
    border-radius: 4px;
  }

  .ctx button:hover {
    background: var(--accent-soft);
  }

  .ctx .danger {
    color: var(--danger);
  }
</style>
