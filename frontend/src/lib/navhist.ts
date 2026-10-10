// Offset navigation history: browser-style back/forward across cursor
// jumps (goto, bookmarks, search hits). Per-document, capped, and pure
// module — no Svelte.

const CAP = 100;

interface Hist {
  back: number[];
  forward: number[];
}

const hists = new Map<number, Hist>();
let lastDoc = 0;
let lastOffset = -1;

function hist(docId: number): Hist {
  let h = hists.get(docId);
  if (!h) {
    h = { back: [], forward: [] };
    hists.set(docId, h);
  }
  return h;
}

/**
 * push records a NEW navigation to offset on docId (user-initiated
 * jumps only). Consecutive duplicates and the initial position are
 * skipped; pushing clears the forward stack like a browser.
 */
export function push(docId: number, offset: number): void {
  if (docId !== lastDoc) {
    lastDoc = docId;
    lastOffset = offset;
    return;
  }
  if (offset === lastOffset) return;
  const h = hist(docId);
  h.back.push(lastOffset);
  if (h.back.length > CAP) h.back.shift();
  h.forward.length = 0;
  lastOffset = offset;
}

/** canBack reports whether history has an entry to return to. */
export function canBack(docId: number): boolean {
  return hist(docId).back.length > 0;
}

/** canForward reports whether a forward entry exists. */
export function canForward(docId: number): boolean {
  return hist(docId).forward.length > 0;
}

/**
 * back pops the last jump and returns the offset to reveal, or null
 * when there is no history. The current position joins the forward
 * stack.
 */
export function back(docId: number): number | null {
  const h = hist(docId);
  const prev = h.back.pop();
  if (prev === undefined) return null;
  if (lastOffset >= 0 && lastDoc === docId) h.forward.push(lastOffset);
  lastOffset = prev;
  return prev;
}

/** forward re-follows a backed-out jump, or null when none exists. */
export function forward(docId: number): number | null {
  const h = hist(docId);
  const next = h.forward.pop();
  if (next === undefined) return null;
  if (lastOffset >= 0 && lastDoc === docId) h.back.push(lastOffset);
  lastOffset = next;
  return next;
}

/** resetFor forgets one document's history (e.g. after close). */
export function resetFor(docId: number): void {
  hists.delete(docId);
  if (lastDoc === docId) lastOffset = -1;
}

/** reset forgets every document's history. */
export function reset(): void {
  hists.clear();
  lastOffset = -1;
}
