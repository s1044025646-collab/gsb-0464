export const GREASE_VALUES: readonly number[] = Object.freeze([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

const GREASE_SET: ReadonlySet<number> = new Set(GREASE_VALUES);

export function isGrease(value: number): boolean {
  return GREASE_SET.has(value);
}
