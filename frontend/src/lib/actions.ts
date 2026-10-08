import { store, flash } from "./state.svelte";
import { svc, models, Dialogs, errMsg } from "./api";
import { ethicsAccepted } from "./ethics";
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
    requestAnimationFrame(() => store.revealFn?.(off));
  } catch (e) {
    flash(errMsg(e));
  }
}

export async function selectAll(): Promise<void> {
  const doc = store.active;
  if (!doc) return;
  store.selStart = 0;
  store.selEnd = doc.size;
  store.cursor = 0;
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
  if (!ethicsAccepted()) {
    store.showEthics = true;
    return;
  }
  store.showBrowser = true;
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
