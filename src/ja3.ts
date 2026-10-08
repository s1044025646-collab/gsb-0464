import { createHash } from "node:crypto";

const GREASE_VALUES = new Set<number>();
for (let hi = 0x0a; hi <= 0xfa; hi += 0x10) {
  GREASE_VALUES.add((hi << 8) | hi);
}

export function isGrease(v: number): boolean {
  return GREASE_VALUES.has(v);
}

export interface Ja3Parts {
  version: number;
  cipherSuites: number[];
  extensions: number[];
  supportedGroups: number[];
  ecPointFormats: number[];
  removed: {
    cipherSuites: number[];
    extensions: number[];
    supportedGroups: number[];
  };
}

export interface Ja3Result extends Ja3Parts {
  ja3: string;
  md5: string;
}

function joinList(values: number[]): string {
  return values.join("-");
}

export function buildJa3(parts: Ja3Parts): Ja3Result {
  const ciphers = parts.cipherSuites.filter((v) => !isGrease(v));
  const exts = parts.extensions.filter((v) => !isGrease(v));
  const groups = parts.supportedGroups.filter((v) => !isGrease(v));
  const ja3 = [
    String(parts.version),
    joinList(ciphers),
    joinList(exts),
    joinList(groups),
    joinList(parts.ecPointFormats),
  ].join(",");
  return {
    ...parts,
    ja3,
    md5: createHash("md5").update(ja3, "utf8").digest("hex"),
  };
}
