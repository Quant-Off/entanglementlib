const UNITS = ["B", "KiB", "MiB", "GiB"] as const;

export function formatBytes(count: number): string {
  if (!Number.isFinite(count) || count < 0) {
    return "0 B";
  }
  let value = count;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rendered = unit === 0 ? String(value) : value.toFixed(1);
  return `${rendered} ${UNITS[unit]}`;
}

export function decodeBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 && ch !== "\n" && ch !== "\r" && ch !== "\t") {
      return null;
    }
  }
  return text;
}

export function toHexDump(bytes: Uint8Array, maxBytes = 4096): string {
  const limit = Math.min(bytes.length, maxBytes);
  const lines: string[] = [];
  for (let offset = 0; offset < limit; offset += 16) {
    const row = bytes.subarray(offset, Math.min(offset + 16, limit));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(row, (b) =>
      b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".",
    ).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (bytes.length > maxBytes) {
    lines.push(`... (${String(bytes.length - maxBytes)} 바이트 생략)`);
  }
  return lines.join("\n");
}
