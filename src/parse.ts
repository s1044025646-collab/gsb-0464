import { HelloStreamParser } from './stream.js';
import { Ja3ParseError } from './errors.js';
import type { ParseOutcome } from './types.js';

export function parseHex(input: string, chunkSize = 0): ParseOutcome {
  const bytes = decodeHex(input);
  return parseBytes(bytes, chunkSize);
}

export function parseBytes(bytes: Buffer, chunkSize = 0): ParseOutcome {
  const parser = new HelloStreamParser();
  if (bytes.length === 0) {
    return parser.finish();
  }
  if (chunkSize && chunkSize > 0) {
    for (let i = 0; i < bytes.length; i += chunkSize) {
      parser.feed(bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
    }
  } else {
    parser.feed(bytes);
  }
  return parser.finish();
}

export function decodeHex(input: string): Buffer {
  const clean = input.replace(/\s+/g, '').replace(/^0x/i, '');
  if (clean.length === 0) return Buffer.alloc(0);
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Ja3ParseError('INVALID_HEX', '十六进制字符串非法（含非 hex 字符或奇数长度）');
  }
  return Buffer.from(clean, 'hex');
}

export function toHex(bytes: Buffer): string {
  return bytes.toString('hex');
}
