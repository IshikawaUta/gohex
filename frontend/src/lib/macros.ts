// Macro recorder/replay: captures examiner navigation actions (goto,
// find, copy, bookmark) as a replayable op list. The recorder bumps
// store.navGen so UI (status-bar REC badge) re-derives reactively.

import { store } from "./state.svelte";

export type MacroOp =
  | { kind: "goto"; expr: string }
  | { kind: "find"; expr: string; forward: boolean; mode: "text" | "hex" | "regex" }
  | { kind: "copy"; what: "hex" | "text" | "offset" }
  | { kind: "bookmark" }
  | { kind: "selectAll" }
  | { kind: "wait"; ms: number };

export interface Macro {
  name: string;
  ops: MacroOp[];
  created: string;
}

const KEY = "gohex.macros.v1";

let recording: MacroOp[] | null = null;

/** isRecording reports whether the recorder is armed. */
export function isRecording(): boolean {
  return recording !== null;
}

/** startRecording arms the recorder (restarting clears prior ops). */
export function startRecording(): void {
  recording = [];
  store.navGen++;
}

/** stopRecording disarms the recorder and returns the captured ops. */
export function stopRecording(): MacroOp[] {
  const ops = recording ?? [];
  recording = null;
  store.navGen++;
  return ops;
}

/** record appends one op when armed; no-op while idle. */
export function record(op: MacroOp): void {
  if (recording) {
    recording.push(op);
    store.navGen++;
  }
}

/** recordedOps returns a copy of the ops captured so far. */
export function recordedOps(): MacroOp[] {
  return [...(recording ?? [])];
}

function load(): Macro[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) return parsed as Macro[];
  } catch {
    // corrupt → start clean
  }
  return [];
}

function save(list: Macro[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    // quota: macros become session-scoped silently
  }
}

/** list returns every saved macro, newest first. */
export function list(): Macro[] {
  return [...load()].sort((a, b) => b.created.localeCompare(a.created));
}

/** saveMacro stores (or replaces, by name) one macro. */
export function saveMacro(name: string, ops: MacroOp[]): boolean {
  const trimmed = name.trim();
  if (!trimmed || ops.length === 0) return false;
  const all = load().filter((m) => m.name !== trimmed);
  all.push({ name: trimmed, ops: [...ops], created: new Date().toISOString() });
  save(all);
  return true;
}

/** removeMacro deletes one macro by name. */
export function removeMacro(name: string): void {
  save(load().filter((m) => m.name !== name));
}

/** get returns one macro by name, or null. */
export function get(name: string): Macro | null {
  return load().find((m) => m.name === name) ?? null;
}

/** exportJSON serialises a macro for file export. */
export function exportJSON(m: Macro): string {
  return JSON.stringify({ format: "gohex-macro-v1", ...m }, null, "\t");
}

/** importJSON parses an exported macro; rejects foreign formats. */
export function importJSON(text: string): Macro | null {
  try {
    const parsed = JSON.parse(text) as Partial<Macro> & { format?: string };
    if (parsed.format !== "gohex-macro-v1") return null;
    if (!parsed.name || !Array.isArray(parsed.ops)) return null;
    const ops = parsed.ops.filter(
      (o): o is MacroOp =>
        !!o && typeof o === "object" && typeof (o as { kind?: unknown }).kind === "string",
    );
    if (ops.length === 0) return null;
    return { name: parsed.name, ops, created: parsed.created ?? new Date().toISOString() };
  } catch {
    return null;
  }
}
