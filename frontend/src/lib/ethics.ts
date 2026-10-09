export type EthicsModule = "browser" | "memory";

const KEYS: Record<EthicsModule, string> = {
  browser: "gohex.ethics.browser.v1",
  memory: "gohex.ethics.memory.v1",
};

/**
 * reports whether the ethics notice of a module has been acknowledged on
 * this machine. docs/legal.md requires the notice the first time such a
 * module (browser artefacts, memory captures, crash dumps) is opened.
 */
export function ethicsAccepted(mod: EthicsModule): boolean {
  try {
    return localStorage.getItem(KEYS[mod]) === "1";
  } catch {
    return false;
  }
}

export function acceptEthics(mod: EthicsModule): void {
  try {
    localStorage.setItem(KEYS[mod], "1");
  } catch {
    /* storage unavailable */
  }
}
