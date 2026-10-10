// Per-file bookmarks: named offsets an examiner drops while working a
// case. Stored in localStorage keyed by evidence path so they survive
// reopening the file (and app restarts). Pure module — no Svelte.

export interface Bookmark {
  offset: number;
  label: string;
  created: string;
}

const KEY = "gohex.bookmarks.v1";

type Store = Record<string, Bookmark[]>; // evidence path → bookmarks

function load(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Store;
    }
  } catch {
    // Corrupt storage: start clean rather than crash the UI.
  }
  return {};
}

function save(s: Store): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    // Quota or privacy mode: bookmarks become session-scoped silently.
  }
}

/** bookmarksFor returns the bookmarks of one evidence file, sorted by offset. */
export function bookmarksFor(path: string): Bookmark[] {
  return [...(load()[path] ?? [])].sort((a, b) => a.offset - b.offset);
}

/** allBookmarks returns every file that has bookmarks, for the picker. */
export function allBookmarks(): Array<{ path: string; bookmarks: Bookmark[] }> {
  const s = load();
  return Object.keys(s)
    .filter((p) => s[p]?.length)
    .sort()
    .map((p) => ({ path: p, bookmarks: bookmarksFor(p) }));
}

/** hasBookmark reports whether path already carries a bookmark at offset. */
export function hasBookmark(path: string, offset: number): boolean {
  return (load()[path] ?? []).some((b) => b.offset === offset);
}

/**
 * addBookmark records offset at path. Duplicate offsets are rejected
 * (returns false) so the star toggle stays idempotent. Labels default
 * to the hex offset; capacity is capped per file to keep the list
 * usable on long sessions.
 */
export function addBookmark(path: string, offset: number, label?: string): boolean {
  const s = load();
  const list = s[path] ?? [];
  if (list.some((b) => b.offset === offset)) return false;
  if (list.length >= 500) return false;
  list.push({
    offset,
    label: label?.trim() || `0x${offset.toString(16).toUpperCase()}`,
    created: new Date().toISOString(),
  });
  s[path] = list;
  save(s);
  return true;
}

/** removeBookmark drops the bookmark at offset (no-op when absent). */
export function removeBookmark(path: string, offset: number): void {
  const s = load();
  const list = s[path];
  if (!list) return;
  s[path] = list.filter((b) => b.offset !== offset);
  if (s[path].length === 0) delete s[path];
  save(s);
}

/** clearBookmarks removes every bookmark of one file. */
export function clearBookmarks(path: string): void {
  const s = load();
  delete s[path];
  save(s);
}
