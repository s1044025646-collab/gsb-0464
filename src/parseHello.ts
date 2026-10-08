import { Ja3ParseError } from './errors.js';
import { LIMITS } from './limits.js';
import type {
  ByteRange,
  ClientHelloFields,
  ExtensionInfo,
  FieldSource,
} from './types.js';
import type { Ja3ErrorCode } from './errors.js';

class Reader {
  offset = 0;
  readonly sources: FieldSource[] = [];

  constructor(private readonly buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  need(n: number, code: Ja3ErrorCode, what: string): void {
    if (this.remaining < n) {
      throw new Ja3ParseError(code, `${what} 需要 ${n} 字节，仅剩 ${this.remaining}`, this.offset);
    }
  }

  u8(what: string, code: Ja3ErrorCode = 'BAD_HANDSHAKE_LENGTH'): number {
    this.need(1, code, what);
    const v = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return v;
  }

  u16(what: string, code: Ja3ErrorCode = 'BAD_HANDSHAKE_LENGTH'): number {
    this.need(2, code, what);
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }

  track(field: string, start: number, len: number): void {
    this.sources.push({ field, handshakeOffset: start, lengthBytes: len, spans: [{ start, endExclusive: start + len }] });
  }
}

export function parseClientHelloBody(body: Buffer): ClientHelloFields {
  const r = new Reader(body);

  const verStart = r.offset;
  const legacyVersion = r.u16('legacy_version');
  r.track('legacy_version', verStart, 2);

  const randomStart = r.offset;
  r.need(LIMITS.randomLength, 'BAD_HANDSHAKE_LENGTH', 'random');
  const randomHex = body.subarray(randomStart, randomStart + LIMITS.randomLength).toString('hex');
  r.offset += LIMITS.randomLength;
  r.track('random', randomStart, LIMITS.randomLength);

  const sidLenStart = r.offset;
  const sidLen = r.u8('session_id.length');
  if (sidLen > LIMITS.maxSessionId) {
    throw new Ja3ParseError('BAD_SESSION_ID', `session_id 长度 ${sidLen} 超过 ${LIMITS.maxSessionId}`, sidLenStart);
  }
  const sidStart = r.offset;
  r.need(sidLen, 'BAD_SESSION_ID', 'session_id');
  const sessionIdHex = body.subarray(sidStart, sidStart + sidLen).toString('hex');
  r.offset += sidLen;
  r.track('session_id', sidLenStart, sidStart - sidLenStart + sidLen);

  const csLenStart = r.offset;
  const csBytes = r.u16('cipher_suites.length');
  if (csBytes < 2 || csBytes % 2 !== 0) {
    throw new Ja3ParseError('BAD_CIPHER_SUITES', `cipher_suites 字节数 ${csBytes} 必须为正偶数`, csLenStart);
  }
  if (csBytes > LIMITS.maxCipherSuitesBytes) {
    throw new Ja3ParseError('BAD_CIPHER_SUITES', `cipher_suites 字节数超限`, csLenStart);
  }
  const csStart = r.offset;
  r.need(csBytes, 'BAD_CIPHER_SUITES', 'cipher_suites');
  const cipherSuites: number[] = [];
  for (let i = 0; i < csBytes; i += 2) {
    cipherSuites.push(body.readUInt16BE(csStart + i));
  }
  r.offset += csBytes;
  r.track('cipher_suites', csLenStart, csStart - csLenStart + csBytes);

  const cmLenStart = r.offset;
  const cmLen = r.u8('compression_methods.length');
  if (cmLen === 0) {
    throw new Ja3ParseError('BAD_COMPRESSION_METHODS', 'compression_methods 向量不能为空', cmLenStart);
  }
  if (cmLen > LIMITS.maxCompressionMethods) {
    throw new Ja3ParseError('BAD_COMPRESSION_METHODS', 'compression_methods 长度超限', cmLenStart);
  }
  const cmStart = r.offset;
  r.need(cmLen, 'BAD_COMPRESSION_METHODS', 'compression_methods');
  const compressionMethods: number[] = [];
  for (let i = 0; i < cmLen; i++) compressionMethods.push(body.readUInt8(cmStart + i));
  r.offset += cmLen;
  r.track('compression_methods', cmLenStart, cmStart - cmLenStart + cmLen);

  const extensions: ExtensionInfo[] = [];
  let supportedGroups: number[] = [];
  let ecPointFormats: number[] = [];

  if (r.remaining === 0) {
    return finalize();
  }

  const extTotalStart = r.offset;
  const extTotal = r.u16('extensions.length', 'BAD_EXTENSIONS_LENGTH');
  const extVectorStart = r.offset;
  if (extTotal > r.remaining) {
    throw new Ja3ParseError('BAD_EXTENSIONS_LENGTH', `扩展总长 ${extTotal} 超过剩余 ${r.remaining}`, extTotalStart);
  }
  const extEnd = extVectorStart + extTotal;
  const seenTypes = new Set<number>();

  while (r.offset < extEnd) {
    const extStart = r.offset;
    const extType = r.u16('extension.type', 'BAD_EXTENSION_LENGTH');
    if (seenTypes.has(extType)) {
      throw new Ja3ParseError('DUPLICATE_EXTENSION', `扩展类型 ${extType} 重复出现`, extStart);
    }
    seenTypes.add(extType);
    const extLen = r.u16('extension.length', 'BAD_EXTENSION_LENGTH');
    const dataStart = r.offset;
    if (extLen > extEnd - dataStart) {
      throw new Ja3ParseError('BAD_EXTENSION_LENGTH', `扩展 ${extType} 声明长度 ${extLen} 越界`, extStart);
    }

    if (extType === 10) {
      supportedGroups = parseSupportedGroups(body, dataStart, extLen);
    } else if (extType === 11) {
      ecPointFormats = parseEcPointFormats(body, dataStart, extLen);
    }

    extensions.push({ type: extType, dataLength: extLen, handshakeOffset: extStart });
    r.offset = dataStart + extLen;
  }

  if (r.offset !== extEnd) {
    throw new Ja3ParseError('BAD_EXTENSIONS_LENGTH', '扩展向量边界不一致', extTotalStart);
  }
  r.track('extensions', extTotalStart, 2 + extTotal);

  if (r.remaining !== 0) {
    throw new Ja3ParseError('BAD_EXTENSIONS_LENGTH', `扩展未覆盖剩余 ${r.remaining} 字节`, extTotalStart);
  }

  return finalize();

  function parseSupportedGroups(body: Buffer, dataStart: number, extLen: number): number[] {
    if (extLen < 2) {
      throw new Ja3ParseError('BAD_SUPPORTED_GROUPS', 'supported_groups 缺少双字节长度', dataStart);
    }
    const listBytes = body.readUInt16BE(dataStart);
    if (listBytes < 2 || listBytes % 2 !== 0) {
      throw new Ja3ParseError('BAD_SUPPORTED_GROUPS', `supported_groups 字节数 ${listBytes} 必须为正偶数`, dataStart);
    }
    if (2 + listBytes !== extLen) {
      throw new Ja3ParseError('BAD_SUPPORTED_GROUPS', `supported_groups 内部长度 ${listBytes} 与扩展载荷 ${extLen} 不一致`, dataStart);
    }
    const groups: number[] = [];
    for (let i = 0; i < listBytes; i += 2) groups.push(body.readUInt16BE(dataStart + 2 + i));
    return groups;
  }

  function parseEcPointFormats(body: Buffer, dataStart: number, extLen: number): number[] {
    if (extLen < 1) {
      throw new Ja3ParseError('BAD_EC_POINT_FORMATS', 'ec_point_formats 缺少单字节长度', dataStart);
    }
    const listLen = body.readUInt8(dataStart);
    if (listLen === 0) {
      throw new Ja3ParseError('BAD_EC_POINT_FORMATS', 'ec_point_formats 向量不能为空', dataStart);
    }
    if (1 + listLen !== extLen) {
      throw new Ja3ParseError('BAD_EC_POINT_FORMATS', `ec_point_formats 内部长度 ${listLen} 与扩展载荷 ${extLen} 不一致`, dataStart);
    }
    const fmts: number[] = [];
    for (let i = 0; i < listLen; i++) fmts.push(body.readUInt8(dataStart + 1 + i));
    return fmts;
  }

  function finalize(): ClientHelloFields {
    return {
      legacyVersion,
      randomHex,
      sessionIdHex,
      cipherSuites,
      compressionMethods,
      extensions,
      supportedGroups,
      ecPointFormats,
      sources: r.sources,
      handshakeBodyLength: body.length,
    };
  }
}
