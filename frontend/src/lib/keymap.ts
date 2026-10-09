// Keymap engine (frontend half): canonicalises KeyboardEvents into the
// same chord strings the Go keymap engine uses ("Ctrl+Shift+S") and
// resolves them against the user's shortcut map. Canonicalisation must
// stay in lockstep with internal/keymap.

const modOrder = ["Ctrl", "Alt", "Shift", "Meta"] as const;

const keyAliases: Record<string, string> = {
  return: "enter",
  esc: "escape",
  pgup: "pageup",
  pgdn: "pagedown",
  del: "delete",
  ins: "insert",
};

const namedKeys = new Set([
  "space",
  "tab",
  "enter",
  "escape",
  "backspace",
  "delete",
  "insert",
  "home",
  "end",
  "pageup",
  "pagedown",
  "up",
  "down",
  "left",
  "right",
]);

const namedDisplay: Record<string, string> = {
  space: "Space",
  tab: "Tab",
  enter: "Enter",
  escape: "Escape",
  backspace: "Backspace",
  delete: "Delete",
  insert: "Insert",
  home: "Home",
  end: "End",
  pageup: "PageUp",
  pagedown: "PageDown",
  up: "Up",
  down: "Down",
  left: "Left",
  right: "Right",
};

/** canonicalBase folds one KeyboardEvent.key onto its canonical base key. */
function canonicalBase(raw: string): string {
  let key = raw.toLowerCase();
  key = keyAliases[key] ?? key;
  if (key.length === 1) {
    if (/[a-z0-9]/.test(key)) return key;
    if ("+-=[];',./\\`".includes(key)) return key;
    return "";
  }
  if (/^f([1-9]|1[0-9]|2[0-4])$/.test(key)) return key;
  if (namedKeys.has(key)) return key;
  return "";
}

/**
 * chordOf renders a KeyboardEvent as the canonical chord string, or ""
 * if the event is not a bindable chord (unknown base key).
 */
export function chordOf(e: KeyboardEvent): string {
  const key = canonicalBase(e.key);
  if (!key) return "";
  const mods: string[] = [];
  if (e.ctrlKey) mods.push("Ctrl");
  if (e.altKey) mods.push("Alt");
  if (e.shiftKey) mods.push("Shift");
  if (e.metaKey) mods.push("Meta");
  // Modifier-only presses ("Control" as key) have no bindable base.
  const set = new Set(mods);
  const ordered = modOrder.filter((m) => set.has(m));
  let disp = key;
  if (key.length === 1 && /[a-z]/.test(key)) disp = key.toUpperCase();
  else if (/^f\d+$/.test(key)) disp = "F" + key.slice(1);
  else if (namedDisplay[key]) disp = namedDisplay[key];
  return [...ordered, disp].join("+");
}

/**
 * findAction returns the action ID bound to the event, or "" when the
 * chord is unbound. Chord comparison is exact on the canonical form, so
 * config values may be written in any casing the Go engine accepts —
 * the service normalises them on save.
 */
export function findAction(
  shortcuts: Record<string, string | null | undefined> | null | undefined,
  e: KeyboardEvent,
): string {
  if (!shortcuts) return "";
  const chord = chordOf(e);
  if (!chord) return "";
  for (const [action, bound] of Object.entries(shortcuts)) {
    if (!bound) continue;
    if (normalize(bound) === chord) return action;
  }
  return "";
}

/** normalize folds a config chord string onto the canonical form. */
function normalize(s: string): string {
  const parts = s.split("+");
  while (parts.length >= 3 && parts[parts.length - 1] === "" && parts[parts.length - 2] === "") {
    parts.pop();
    parts[parts.length - 1] = "+";
  }
  if (parts.length >= 2 && parts[parts.length - 1] === "") {
    const prev = parts[parts.length - 2].toLowerCase();
    if (["ctrl", "control", "alt", "opt", "option", "shift", "meta", "cmd", "command", "super", "win"].includes(prev)) {
      parts[parts.length - 1] = "+";
    }
  }
  const mods: string[] = [];
  let base = "";
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].toLowerCase().trim();
    if (!p) return "";
    const last = i === parts.length - 1;
    if (!last) {
      const m = aliasMod(p);
      if (!m) return "";
      if (!mods.includes(m)) mods.push(m);
      continue;
    }
    base = p;
  }
  if (!base) return "";
  let disp = base;
  if (base.length === 1 && /[a-z]/.test(base)) disp = base.toUpperCase();
  else if (/^f\d+$/.test(base)) disp = "F" + base.slice(1);
  else if (namedDisplay[base]) disp = namedDisplay[base];
  const ordered = modOrder.filter((m) => mods.includes(m));
  return [...ordered, disp].join("+");
}

function aliasMod(p: string): string | null {
  switch (p) {
    case "ctrl":
    case "control":
      return "Ctrl";
    case "alt":
    case "opt":
    case "option":
      return "Alt";
    case "shift":
      return "Shift";
    case "meta":
    case "cmd":
    case "command":
    case "super":
    case "win":
      return "Meta";
    default:
      return null;
  }
}
