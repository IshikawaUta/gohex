import type { DocInfo } from "../../bindings/github.com/IshikawaUta/gohex/internal/service/models";
import type { Preferences } from "../../bindings/github.com/IshikawaUta/gohex/internal/config/models";

export type ThemeName = "dark" | "light" | "high-contrast";

class Store {
  docs = $state<DocInfo[]>([]);
  activeId = $state(0);
  prefs = $state<Preferences | null>(null);
  catalog = $state<Record<string, string>>({});
  catalogLang = $state("");
  cursor = $state(0);
  selStart = $state(0);
  selEnd = $state(0);
  statusMsg = $state("");
  progress = $state<{ op: string; done: number } | null>(null);
  showDisclaimer = $state(false);
  showAbout = $state(false);
  showPrefs = $state(false);
  showDisk = $state(false);
  showCarve = $state(false);
  showEthics = $state(false);
  ethicsTarget = $state<"browser" | "memory">("browser");
  showBrowser = $state(false);
  showMemory = $state(false);
  showCase = $state(false);
  showScript = $state(false);
  showTemplate = $state(false);
  showDump = $state(false);
  showCompare = $state(false);
  findOpen = $state(false);
  pendingNibble = $state(-1);
  revealFn: ((off: number, selLen?: number) => void) | null = null;
  copyFn: ((kind: "hex" | "text" | "offset") => Promise<void>) | null = null;

  get active(): DocInfo | undefined {
    return this.docs.find((d) => d.id === this.activeId);
  }

  get lang(): string {
    return this.prefs?.language || "en";
  }

  get theme(): ThemeName {
    return (this.prefs?.theme as ThemeName) || "dark";
  }

  get bytesPerLine(): number {
    const n = this.prefs?.bytesPerLine ?? 16;
    return [8, 16, 32].includes(n) ? n : 16;
  }

  get editable(): boolean {
    return !!this.active?.editingAllowed;
  }

  t(key: string): string {
    return this.catalog[key] ?? key;
  }
}

export const store = new Store();

let statusTimer: ReturnType<typeof setTimeout> | undefined;

export function flash(msg: string): void {
  store.statusMsg = msg;
  clearTimeout(statusTimer);
  statusTimer = setTimeout(() => {
    if (store.statusMsg === msg) store.statusMsg = "";
  }, 4000);
}
