const KEY = "gohex.ethics.browser.v1";

/**
 * reports whether the browser-artefact ethics notice has been acknowledged
 * on this machine. docs/legal.md requires the notice the first time such a
 * module is opened.
 */
export function ethicsAccepted(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function acceptEthics(): void {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    /* storage unavailable */
  }
}
