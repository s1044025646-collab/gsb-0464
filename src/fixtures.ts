// 手工构造 TLS ClientHello 夹具（离线字节布局，不依赖网络）
export interface Fixture {
  name: string;
  description: string;
  build: () => Buffer;
}

function u16(v: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(v);
  return b;
}

function record(payload: Buffer, version = 0x0301): Buffer {
  const header = Buffer.from([22, version >> 8, version & 0xff, 0, 0]);
  header.writeUInt16BE(payload.length, 3);
  return Buffer.concat([header, payload]);
}

function handshake(body: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header[0] = 1; // ClientHello
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

export interface HelloOptions {
  legacyVersion?: number;
  cipherSuites?: number[];
  compressionMethods?: number[];
  sessionId?: Buffer;
  extensions?: { type: number; data: Buffer }[] | null; // null = 无扩展块
}

export function buildHelloBody(opts: HelloOptions = {}): Buffer {
  const legacyVersion = opts.legacyVersion ?? 0x0303; // 771
  const ciphers = opts.cipherSuites ?? [0x1301, 0x1302]; // 4865,4866
  const comp = opts.compressionMethods ?? [0];
  const sessionId = opts.sessionId ?? Buffer.alloc(0);
  const random = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) random[i] = i;

  const cipherBytes = Buffer.concat(ciphers.map(u16));
  const parts: Buffer[] = [
    u16(legacyVersion),
    random,
    Buffer.from([sessionId.length]),
    sessionId,
    u16(cipherBytes.length),
    cipherBytes,
    Buffer.from([comp.length]),
    Buffer.from(comp),
  ];

  const exts =
    opts.extensions === undefined
      ? [
          { type: 10, data: Buffer.concat([u16(4), u16(29), u16(23)]) },
          { type: 11, data: Buffer.from([1, 0]) },
        ]
      : opts.extensions;
  if (exts !== null) {
    const extBlock = Buffer.concat(
      exts.map((e) => Buffer.concat([u16(e.type), u16(e.data.length), e.data]))
    );
    parts.push(u16(extBlock.length), extBlock);
  }
  return Buffer.concat(parts);
}

export function wrapRecords(
  body: Buffer,
  split?: { recordSplit?: number[]; handshakeSplit?: number }
): Buffer {
  const hs = handshake(body);
  if (split?.handshakeSplit !== undefined) {
    // 把握手消息按指定位置切成两条记录
    const at = split.handshakeSplit;
    return Buffer.concat([record(hs.subarray(0, at)), record(hs.subarray(at))]);
  }
  if (split?.recordSplit && split.recordSplit.length > 0) {
    const out: Buffer[] = [];
    let offset = 0;
    for (const size of split.recordSplit) {
      out.push(record(hs.subarray(offset, offset + size)));
      offset += size;
    }
    if (offset < hs.length) out.push(record(hs.subarray(offset)));
    return Buffer.concat(out);
  }
  return record(hs);
}

const GREASE = 0x1a1a;

export const FIXTURES: Fixture[] = [
  {
    name: "known",
    description: "已知样例：771,4865-4866,10-11,29-23,0",
    build: () => wrapRecords(buildHelloBody()),
  },
  {
    name: "known-grease",
    description: "插入 GREASE 的等价样例，指纹与 known 相同",
    build: () =>
      wrapRecords(
        buildHelloBody({
          cipherSuites: [GREASE, 0x1301, 0x1302],
          extensions: [
            { type: GREASE, data: Buffer.alloc(0) },
            { type: 10, data: Buffer.concat([u16(6), u16(GREASE), u16(29), u16(23)]) },
            { type: 11, data: Buffer.from([1, 0]) },
          ],
        })
      ),
  },
  {
    name: "known-reordered",
    description: "调换普通套件次序，指纹不同",
    build: () => wrapRecords(buildHelloBody({ cipherSuites: [0x1302, 0x1301] })),
  },
  {
    name: "cross-record",
    description: "ClientHello 跨两条 TLS 记录",
    build: () => wrapRecords(buildHelloBody(), { handshakeSplit: 20 }),
  },
  {
    name: "no-extensions",
    description: "握手体在压缩方法后结束，无扩展块",
    build: () => wrapRecords(buildHelloBody({ extensions: null })),
  },
  {
    name: "unknown-extension",
    description: "包含未知扩展 0x0028，仅保留类型与顺序",
    build: () =>
      wrapRecords(
        buildHelloBody({
          extensions: [
            { type: 10, data: Buffer.concat([u16(4), u16(29), u16(23)]) },
            { type: 0x0028, data: Buffer.from([1, 2, 3]) },
            { type: 11, data: Buffer.from([1, 0]) },
          ],
        })
      ),
  },
  {
    name: "with-tail",
    description: "首个 Hello 后同一记录内还有多余字节（报告尾部，不混入）",
    build: () => {
      const hs = handshake(buildHelloBody());
      const payload = Buffer.concat([hs, Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
      return record(payload);
    },
  },
];

export function getFixture(name: string): Fixture | undefined {
  return FIXTURES.find((f) => f.name === name);
}
