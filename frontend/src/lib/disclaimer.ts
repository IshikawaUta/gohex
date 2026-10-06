const KEY = "gohex.disclaimer.v2";

export function disclaimerAccepted(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function acceptDisclaimer(): void {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    /* storage unavailable */
  }
}
