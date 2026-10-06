export function hexOffset(off: number, digits: number): string {
  return off.toString(16).toUpperCase().padStart(digits, "0");
}

export function offsetDigits(size: number): number {
  return Math.max(8, Math.ceil(Math.max(size, 1).toString(16).length / 2) * 2);
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let u = -1;
  do {
    v /= 1024;
    u++;
  } while (v >= 1024 && u < units.length - 1);
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`;
}

export function fmtOffsetHex(off: number): string {
  return `0x${off.toString(16).toUpperCase().padStart(8, "0")}`;
}

const printable = (b: number): string => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");

export function hexBytes(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).toUpperCase().padStart(2, "0");
  return out;
}
