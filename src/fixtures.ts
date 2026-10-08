import { decodeHex } from './parse.js';

export interface HelloOptions {
  version?: number;
  random?: Buffer | string;
  sessionId?: Buffer | string;
  cipherSuites?: number[];
  compressionMethods?: number[];
  greaseCipherAt?: number;
  greaseExtAt?: number;
  greaseGroupAt?: number;
  supportedGroups?: number[];
  ecPointFormats?: number;
  unknownExtensions?: Array<{ type: number; data: Buffer | string }>;
  includeExtensions?: boolean;
}

export interface BuiltHello {
  bytes: Buffer;
  handshake: Buffer;
}

function asBytes(v: Buffer | string | undefined, fallback: Buffer): Buffer {
  if (v === undefined) return fallback;
  return typeof v === 'string' ? decodeHex(v) : v;
}

export function buildClientHello(opts: HelloOptions = {}): BuiltHello {
  const version = opts.version ?? 0x0303;
  const random = asBytes(opts.random, Buffer.alloc(32, 0x42));
  const sessionId = asBytes(opts.sessionId, Buffer.alloc(0));

  let ciphers = opts.cipherSuites ?? [0x1301, 0x1302];
  if (opts.greaseCipherAt !== undefined) {
    const next = [...ciphers];
    next.splice(opts.greaseCipherAt, 0, 0x0a0a);
    ciphers = next;
  }
  const compressions = opts.compressionMethods ?? [0];

  const body: Buffer[] = [];
  body.push(u16(version));
  body.push(random);
  body.push(Buffer.from([sessionId.length]));
  body.push(sessionId);
  body.push(u16(ciphers.length * 2));
  body.push(Buffer.concat(ciphers.map(u16)));
  body.push(Buffer.from([compressions.length]));
  body.push(Buffer.from(compressions));

  if (opts.includeExtensions !== false) {
    const extList: Array<{ type: number; buf: Buffer }> = [];

    const groups = opts.supportedGroups ?? [29, 23];
    const finalGroups = opts.greaseGroupAt !== undefined
      ? [...groups.slice(0, opts.greaseGroupAt), 0x1a1a, ...groups.slice(opts.greaseGroupAt)]
      : groups;
    const groupsBody = Buffer.concat([u16(finalGroups.length * 2), ...finalGroups.map(u16)]);
    extList.push({ type: 10, buf: extension(10, groupsBody) });

    const pointCount = opts.ecPointFormats ?? 0;
    const ecBody = Buffer.concat([
      Buffer.from([1]),
      Buffer.from([pointCount]),
    ]);
    extList.push({ type: 11, buf: extension(11, ecBody) });

    for (const u of opts.unknownExtensions ?? []) {
      extList.push({ type: u.type, buf: extension(u.type, asBytes(u.data, Buffer.alloc(0))) });
    }

    if (opts.greaseExtAt !== undefined) {
      extList.splice(opts.greaseExtAt, 0, { type: 0x2a2a, buf: extension(0x2a2a, Buffer.alloc(0)) });
    }

    const extBuf = Buffer.concat(extList.map((e) => e.buf));
    body.push(u16(extBuf.length));
    body.push(extBuf);
  }

  const handshakeBody = Buffer.concat(body);
  const hs = Buffer.concat([
    Buffer.from([1, (handshakeBody.length >> 16) & 0xff, (handshakeBody.length >> 8) & 0xff, handshakeBody.length & 0xff]),
    handshakeBody,
  ]);
  return { bytes: hs, handshake: hs };
}

export function wrapRecords(handshake: Buffer, recordVersion = 0x0301, splitAt?: number[]): Buffer {
  const pieces: Buffer[] = [];
  const cuts = splitAt && splitAt.length > 0 ? [...splitAt] : [handshake.length];
  let pos = 0;
  for (const cut of cuts) {
    const piece = handshake.subarray(pos, cut);
    pos = cut;
    pieces.push(record(piece, recordVersion));
  }
  if (pos < handshake.length) pieces.push(record(handshake.subarray(pos), recordVersion));
  return Buffer.concat(pieces);
}

export function record(payload: Buffer, version = 0x0301): Buffer {
  if (payload.length > 0xffff) throw new Error('记录载荷过长');
  return Buffer.concat([
    Buffer.from([22, (version >> 8) & 0xff, version & 0xff, (payload.length >> 8) & 0xff, payload.length & 0xff]),
    payload,
  ]);
}

function extension(type: number, data: Buffer): Buffer {
  return Buffer.concat([u16(type), u16(data.length), data]);
}

function u16(v: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(v & 0xffff, 0);
  return b;
}
