import { store, flash } from "./state.svelte";
import { svc, models, Dialogs, Clipboard, errMsg } from "./api";
import { ethicsAccepted } from "./ethics";
import * as NH from "./navhist";
import * as NM from "./macros";
import * as BM from "./bookmarks";
import { fmtOffsetHex } from "./format";
import type { Preferences } from "../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

export async function refreshDocs(): Promise<void> {
  store.docs = (await svc.ListDocuments()) ?? [];
  if (!store.docs.some((d) => d.id === store.activeId)) {
    store.activeId = store.docs[0]?.id ?? 0;
    syncSelectionFromDoc();
  }
}

export function syncSelectionFromDoc(): void {
  const d = store.active;
  if (!d) return;
  store.cursor = d.cursor;
  store.selStart = d.selStart;
  store.selEnd = d.selEnd;
  store.pendingNibble = -1;
}

export async function loadPrefs(): Promise<void> {
  store.prefs = await svc.Preferences();
}

export async function loadCatalog(): Promise<void> {
  store.catalog = (await svc.Catalog(store.lang)) as Record<string, string>;
  store.catalogLang = store.lang;
}

export async function applyTheme(): Promise<void> {
  document.documentElement.dataset.theme = store.theme;
}

export async function openFile(path?: string): Promise<void> {
  let target = path;
  if (!target) {
    try {
      const res = await Dialogs.OpenFile({
        Title: store.t("menu.file.open"),
        CanChooseFiles: true,
        CanChooseDirectories: false,
        AllowsMultipleSelection: false,
      });
      if (Array.isArray(res)) target = res[0];
      else target = res;
    } catch (e) {
      flash(`Open dialog failed: ${errMsg(e)}`);
      return;
    }
  }
  if (!target) return;
  try {
    const doc = await svc.OpenFile(target);
    store.activeId = doc.id;
    await refreshDocs();
    syncSelectionFromDoc();
    requestAnimationFrame(() => store.revealFn?.(doc.cursor));
    flash(`${doc.name} — ${doc.size} bytes`);
  } catch (e) {
    flash(`Open failed: ${errMsg(e)}`);
  }
}

export async function newDocument(): Promise<void> {
  try {
    const doc = await svc.NewDocument();
    store.activeId = doc.id;
    await refreshDocs();
    syncSelectionFromDoc();
    requestAnimationFrame(() => store.revealFn?.(0));
    flash(`${doc.name} — ${doc.size} bytes`);
  } catch (e) {
    flash(`New document failed: ${errMsg(e)}`);
  }
}

export async function closeDocument(id: number): Promise<void> {
  const doc = store.docs.find((d) => d.id === id);
  if (doc?.dirty) {
    const ans = await Dialogs.Question({
      Title: store.t("menu.file.close"),
      Message: `${doc.name} has unsaved changes. Close anyway?`,
    });
    if (ans !== "Yes") return;
  }
  try {
    await svc.CloseDocument(id);
    await refreshDocs();
    syncSelectionFromDoc();
  } catch (e) {
    flash(errMsg(e));
  }
}

export async function saveActive(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  if (!doc.path) {
    await saveActiveAs();
    return;
  }
  try {
    const res = await svc.Save(doc.id);
    await refreshDocs();
    flashSaved(res);
  } catch (e) {
    await Dialogs.Error({ Title: store.t("error.saveFailed"), Message: errMsg(e) });
  }
}

export async function saveActiveAs(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  try {
    const chosen = await Dialogs.SaveFile({
      Title: store.t("menu.file.saveAs"),
      Filename: doc.name || "untitled.bin",
    });
    if (!chosen) return;
    const res = await svc.SaveAs(doc.id, chosen);
    await refreshDocs();
    flashSaved(res);
  } catch (e) {
    await Dialogs.Error({ Title: store.t("error.saveFailed"), Message: errMsg(e) });
  }
}

function flashSaved(res: models.SaveResult): void {
  const mode = res.mode === "sandbox" ? " (sandbox — disk untouched)" : "";
  flash(`Saved ${res.bytesSaved} bytes → ${res.path}${mode}`);
}

export async function undo(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  try {
    const label = await svc.Undo(doc.id);
    await refreshDocs();
    syncSelectionFromDoc();
    flash(`Undo: ${label}`);
    requestAnimationFrame(() => store.revealFn?.(store.cursor));
  } catch (e) {
    flash(errMsg(e));
  }
}

export async function redo(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  try {
    const label = await svc.Redo(doc.id);
    await refreshDocs();
    syncSelectionFromDoc();
    flash(`Redo: ${label}`);
    requestAnimationFrame(() => store.revealFn?.(store.cursor));
  } catch (e) {
    flash(errMsg(e));
  }
}

export async function setEncoding(enc: string): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  try {
    await svc.SetEncoding(doc.id, enc);
    await refreshDocs();
    flash(`${store.t("status.encoding")}: ${enc}`);
  } catch (e) {
    flash(errMsg(e));
  }
}

export async function gotoOffset(expr: string): Promise<void> {
  const doc = store.active;
  if (!doc || !expr.trim()) return;
  try {
    const off = await svc.Goto(doc.id, expr.trim());
    await refreshDocs();
    store.cursor = off;
    store.selStart = off;
    store.selEnd = off;
    NM.record({ kind: "goto", expr: expr.trim() });
    NH.push(doc.id, off);
    store.navGen++;
    requestAnimationFrame(() => store.revealFn?.(off));
  } catch (e) {
    flash(errMsg(e));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * replayMacro executes a macro's ops in order against the ACTIVE
  * document. Failures stop the run with a message naming the step —
 * a macro that no longer matches its evidence must not silently
 * continue and misreport where it landed.
 */
export async function replayMacro(m: NM.Macro): Promise<void> {
  if (!store.active) {
    flash("Open a document before replaying a macro");
    return;
  }
  if (NM.isRecording()) {
    flash("Stop recording before replaying");
    return;
  }
  flash(`Replaying macro "${m.name}" (${m.ops.length} ops)…`);
  for (let i = 0; i < m.ops.length; i++) {
    const op = m.ops[i];
    const step = `${i + 1}/${m.ops.length}`;
    try {
      switch (op.kind) {
        case "goto":
          await gotoOffset(op.expr);
          break;
        case "find":
          await replayFind(op.expr, op.forward ? "next" : "prev", op.mode);
          break;
        case "copy":
          await store.copyFn?.(op.what);
          flash(`Step ${step}: copied ${op.what}`);
          break;
        case "bookmark": {
          const doc = store.active;
          if (doc?.path) {
            BM.addBookmark(doc.path, store.cursor);
            store.navGen++;
            flash(`Step ${step}: bookmarked ${fmtOffsetHex(store.cursor)}`);
          }
          break;
        }
        case "selectAll":
          await selectAll();
          break;
        case "wait":
          await sleep(Math.min(10_000, Math.max(0, op.ms)));
          break;
      }
    } catch (e) {
      flash(`Macro "${m.name}" stopped at step ${step}: ${errMsg(e)}`);
      return;
    }
  }
  flash(`Macro "${m.name}" finished (${m.ops.length} ops)`);
}

async function replayFind(
  pattern: string,
  direction: "next" | "prev",
  mode: "text" | "hex" | "regex",
): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  const res = await svc.Find({
    id: doc.id,
    mode,
    pattern,
    encoding: doc.encoding,
    caseFold: true,
    direction,
    from: store.cursor,
    wrap: true,
    max: 0,
  });
  const m = res.count > 0 ? (res.matches ?? [])[0] : undefined;
  if (m) {
    store.revealFn?.(m.start, m.length);
  } else {
    throw new Error(`pattern ${JSON.stringify(pattern)} not found`);
  }
}

export async function selectAll(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  store.selStart = 0;
  store.selEnd = doc.size;
  store.cursor = 0;
  NM.record({ kind: "selectAll" });
  await svc.SetSelection(doc.id, 0, doc.size).catch(() => {});
  store.revealFn?.(0);
}

export async function hashActive(algo: string, selectionOnly: boolean): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  try {
    store.progress = { op: "hash", done: 0 };
    const sum = await svc.HashDocument(doc.id, algo, selectionOnly);
    store.progress = null;
    flash(sum);
  } catch (e) {
    store.progress = null;
    await Dialogs.Error({ Title: "Hash", Message: errMsg(e) });
  }
}

export function openBrowser(): void {
  if (!ethicsAccepted("browser")) {
    store.ethicsTarget = "browser";
    store.showEthics = true;
    return;
  }
  store.showBrowser = true;
}

export function openMemory(): void {
  if (!ethicsAccepted("memory")) {
    store.ethicsTarget = "memory";
    store.showEthics = true;
    return;
  }
  store.showMemory = true;
}

export async function preferencesChanged(next: Preferences): Promise<void> {
  try {
    await svc.SetPreferences(next);
    store.prefs = await svc.Preferences();
    await applyTheme();
    if (store.lang !== store.catalogLang) await loadCatalog();
    flash("Preferences saved");
  } catch (e) {
    await Dialogs.Error({ Title: "Preferences", Message: errMsg(e) });
  }
}
