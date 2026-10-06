import * as svc from "../../bindings/github.com/IshikawaUta/gohex/internal/service/app";
import * as models from "../../bindings/github.com/IshikawaUta/gohex/internal/service/models";
import * as cfgmodels from "../../bindings/github.com/IshikawaUta/gohex/internal/config/models";
import { Dialogs, Clipboard, Events } from "@wailsio/runtime";

export { svc, models, cfgmodels, Dialogs, Clipboard, Events };

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  return String(e);
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
