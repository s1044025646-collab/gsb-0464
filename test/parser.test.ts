import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseBytes, parseHex } from '../src/parse.js';
import { buildClientHello, wrapRecords } from '../src/fixtures.js';

const EXPECTED_TEXT = '771,4865-4866,10-11,29-23,0';
const EXPECTED_MD5 = createHash('md5').update(EXPECTED_TEXT).digest('hex');

function baseBytes(): Buffer {
  return wrapRecords(buildClientHello({
    version: 0x0303,
    cipherSuites: [4865, 4866],
    supportedGroups: [29, 23],
    ecPointFormats: 0,
  }).bytes);
}

test('基准样例产生已知 JA3 字符串与 MD5', () => {
  const r = parseBytes(baseBytes());
  assert.equal(r.ok, true);
  assert.equal(r.ja3!.text, EXPECTED_TEXT);
  assert.equal(r.ja3!.md5, EXPECTED_MD5);
});

test('分块方式不改变字段与摘要', () => {
  const bytes = baseBytes();
  const ref = parseBytes(bytes);
  for (const chunk of [1, 2, 3, 5, 7, 13, 64, 1000]) {
    const r = parseBytes(bytes, chunk);
    assert.equal(r.ok, true, `chunk=${chunk}`);
    assert.equal(r.ja3!.md5, ref.ja3!.md5, `chunk=${chunk}`);
    assert.deepEqual(r.fields!.cipherSuites, ref.fields!.cipherSuites);
  }
});

test('跨记录头与跨握手体', () => {
  const hs = buildClientHello({ cipherSuites: [4865, 4866], supportedGroups: [29, 23] }).bytes;
  for (const cut of [1, 4, 5, 6, 10, hs.length - 1]) {
    const bytes = wrapRecords(hs, 0x0301, [cut, hs.length]);
    const r = parseBytes(bytes, 1);
    assert.equal(r.ok, true, `cut=${cut}: ${r.error?.code}`);
    assert.equal(r.records.length, 2);
    assert.equal(r.ja3!.text, EXPECTED_TEXT);
  }
});

test('GREASE 被剔除且保持顺序，指纹等价', () => {
  const g = wrapRecords(buildClientHello({
    version: 0x0303,
    cipherSuites: [4865, 4866],
    supportedGroups: [29, 23],
    greaseCipherAt: 1,
    greaseExtAt: 0,
    greaseGroupAt: 1,
  }).bytes);
  const r = parseBytes(g);
  assert.equal(r.ok, true);
  assert.deepEqual(r.ja3!.removed.cipherSuites, [0x0a0a]);
  assert.deepEqual(r.ja3!.removed.extensionTypes, [0x2a2a]);
  assert.deepEqual(r.ja3!.removed.supportedGroups, [0x1a1a]);
  assert.deepEqual(r.ja3!.raw.cipherSuites, [4865, 0x0a0a, 4866]);
  assert.equal(r.ja3!.text, EXPECTED_TEXT);
  assert.equal(r.ja3!.md5, EXPECTED_MD5);
});

test('调换普通套件次序产生不同指纹', () => {
  const swapped = wrapRecords(buildClientHello({ cipherSuites: [4866, 4865], supportedGroups: [29, 23] }).bytes);
  const r = parseBytes(swapped);
  assert.equal(r.ok, true);
  assert.equal(r.ja3!.text, '771,4866-4865,10-11,29-23,0');
  assert.notEqual(r.ja3!.md5, EXPECTED_MD5);
});

test('无扩展：握手体恰在 compression_methods 后结束', () => {
  const bytes = wrapRecords(buildClientHello({ includeExtensions: false }).bytes);
  const r = parseBytes(bytes);
  assert.equal(r.ok, true);
  assert.equal(r.ja3!.text, '771,4865-4866,,,');
});

test('未知扩展保留类型与顺序', () => {
  const bytes = wrapRecords(buildClientHello({
    cipherSuites: [4865, 4866],
    supportedGroups: [29, 23],
    unknownExtensions: [{ type: 1234, data: Buffer.from([1, 2, 3]) }],
  }).bytes);
  const r = parseBytes(bytes);
  assert.equal(r.ok, true);
  assert.deepEqual(r.ja3!.raw.extensionTypes, [10, 11, 1234]);
  assert.equal(r.ja3!.text, '771,4865-4866,10-11-1234,29-23,0');
});

test('TLS1.3 样例 JA3 版本仍取 legacy_version', () => {
  const bytes = wrapRecords(buildClientHello({
    version: 0x0303,
    cipherSuites: [4865, 4866],
    supportedGroups: [29, 23],
    unknownExtensions: [{ type: 43, data: Buffer.from([0x04, 0x03, 0x04]) }],
  }).bytes);
  const r = parseBytes(bytes);
  assert.equal(r.ok, true);
  assert.equal(r.ja3!.raw.version, 0x0303);
  assert.equal(r.ja3!.text.split(',')[0], '771');
});

test('finish 时截断报 TRUNCATED_INPUT', () => {
  const bytes = baseBytes();
  for (const cut of [0, 1, 4, 10, bytes.length - 1]) {
    const r = parseBytes(bytes.subarray(0, cut));
    if (cut === 0) {
      assert.equal(r.error!.code, 'EMPTY_INPUT');
    } else {
      assert.equal(r.ok, false);
      assert.equal(r.truncated, true);
      assert.equal(r.error!.code, 'TRUNCATED_INPUT');
    }
  }
});

test('拒绝非 22 记录类型', () => {
  const bytes = Buffer.from(baseBytes());
  bytes[0] = 23;
  const r = parseBytes(bytes);
  assert.equal(r.error!.code, 'UNSUPPORTED_RECORD_TYPE');
});

test('拒绝非 ClientHello 首消息', () => {
  const hs = buildClientHello().bytes;
  hs[0] = 2;
  const bytes = wrapRecords(hs);
  const r = parseBytes(bytes);
  assert.equal(r.error!.code, 'NON_CLIENTHELLO_FIRST_MESSAGE');
});

test('奇数 cipher_suites 字节数', () => {
  const hs = buildClientHello({ includeExtensions: false }).bytes;
  const csLenOffset = 4 + 2 + 32 + 1 + 0;
  hs.writeUInt16BE(3, csLenOffset);
  const r = parseBytes(wrapRecords(hs));
  assert.equal(r.error!.code, 'BAD_CIPHER_SUITES');
});

test('扩展总长度差一被拒绝', () => {
  const hs = buildClientHello({ cipherSuites: [4865, 4866], supportedGroups: [29, 23] }).bytes;
  const r0 = parseBytes(wrapRecords(Buffer.from(hs)));
  assert.ok(r0.ok);
  const extLenOffset = hs.length - (2 + 4 + 6 + 4 + 2) + 0;
  void extLenOffset;
  const copy = Buffer.from(hs);
  const totalLenAt = findExtensionsLengthOffset(copy);
  copy.writeUInt16BE(copy.readUInt16BE(totalLenAt) + 1, totalLenAt);
  const r = parseBytes(wrapRecords(copy));
  assert.equal(r.error!.code, 'BAD_EXTENSIONS_LENGTH');
});

test('supported_groups 元素宽度/内部长度错误', () => {
  const bytes = wrapRecords(buildClientHello({ cipherSuites: [4865], supportedGroups: [29, 23] }).bytes);
  const r = parseBytes(bytes);
  const ext10Offset = r.fields!.sources.find((s) => s.field === 'extensions')!.handshakeOffset;
  void ext10Offset;
  const hs = buildClientHello({ cipherSuites: [4865], supportedGroups: [29, 23] }).bytes;
  const off = findExtensionDataOffset(hs, 10);
  hs.writeUInt16BE(3, off);
  const bad = parseBytes(wrapRecords(hs));
  assert.equal(bad.error!.code, 'BAD_SUPPORTED_GROUPS');
});

test('重复扩展类型被拒绝', () => {
  const bytes = wrapRecords(buildClientHello({
    cipherSuites: [4865, 4866],
    supportedGroups: [29, 23],
    unknownExtensions: [{ type: 10, data: Buffer.alloc(0) }],
  }).bytes);
  const r = parseBytes(bytes);
  assert.equal(r.error!.code, 'DUPLICATE_EXTENSION');
});

test('记录内尾部字节单独报告且不混入 Hello', () => {
  const hs = buildClientHello({ cipherSuites: [4865, 4866], supportedGroups: [29, 23] }).bytes;
  const bytes = wrapRecords(Buffer.concat([hs, Buffer.from([0xaa, 0xbb])]));
  const r = parseBytes(bytes);
  assert.equal(r.ok, true);
  assert.equal(r.firstRecordTrailingBytes, 2);
  assert.equal(r.bytesConsumed, 5 + hs.length);
});

test('字段来源给出跨记录字节区间', () => {
  const hs = buildClientHello({ cipherSuites: [4865, 4866], supportedGroups: [29, 23] }).bytes;
  const bytes = wrapRecords(hs, 0x0301, [9, hs.length]);
  const r = parseBytes(bytes, 1);
  assert.equal(r.ok, true);
  const version = r.fields!.sources.find((s) => s.field === 'legacy_version')!;
  assert.equal(version.spans.length, 1);
  const spans = version.spans.flatMap((s) => [s.start, s.endExclusive]);
  assert.ok(spans.every((n) => Number.isInteger(n)));
});

test('压缩方法向量不能为空', () => {
  const hs = buildClientHello({ includeExtensions: false, compressionMethods: [0] }).bytes;
  const cmLenOffset = 4 + 2 + 32 + 1 + 2 + 4 + 1 - 1;
  void cmLenOffset;
  const csBytes = 4;
  const off = 4 + 2 + 32 + 1 + 0 + 2 + csBytes;
  hs[off] = 0;
  const r = parseBytes(wrapRecords(hs));
  assert.equal(r.error!.code, 'BAD_COMPRESSION_METHODS');
});

test('十六进制入口与二进制一致', () => {
  const bytes = baseBytes();
  const a = parseBytes(bytes);
  const b = parseHex(bytes.toString('hex'));
  assert.equal(b.ja3!.md5, a.ja3!.md5);
});

function findExtensionsLengthOffset(hs: Buffer): number {
  let o = 4;
  o += 2 + 32;
  const sidLen = hs[o]!;
  o += 1 + sidLen;
  const csBytes = hs.readUInt16BE(o);
  o += 2 + csBytes;
  const cmLen = hs[o]!;
  o += 1 + cmLen;
  return o;
}

function findExtensionDataOffset(hs: Buffer, type: number): number {
  const extLenAt = findExtensionsLengthOffset(hs);
  let o = extLenAt + 2;
  const end = o + hs.readUInt16BE(extLenAt);
  while (o < end) {
    const t = hs.readUInt16BE(o);
    const l = hs.readUInt16BE(o + 2);
    if (t === type) return o + 4;
    o += 4 + l;
  }
  throw new Error('扩展未找到');
}
