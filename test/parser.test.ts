import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { parseClientHello, ClientHelloParser } from "../src/parser.js";
import { buildHelloBody, wrapRecords, getFixture } from "../src/fixtures.js";
import { ParseError } from "../src/errors.js";

const KNOWN_JA3 = "771,4865-4866,10-11,29-23,0";

function fixtureBytes(name: string): Buffer {
  const f = getFixture(name);
  assert.ok(f, `fixture ${name}`);
  return f.build();
}

test("known sample JA3 and MD5", () => {
  const r = parseClientHello(fixtureBytes("known"));
  assert.equal(r.ja3.ja3, KNOWN_JA3);
  assert.equal(r.ja3.md5, createHash("md5").update(KNOWN_JA3).digest("hex"));
  assert.equal(r.legacyVersion, 0x0303);
  assert.deepEqual(r.cipherSuites, [0x1301, 0x1302]);
  assert.deepEqual(r.supportedGroups, [29, 23]);
  assert.deepEqual(r.ecPointFormats, [0]);
});

test("GREASE removed, same fingerprint", () => {
  const r = parseClientHello(fixtureBytes("known-grease"));
  assert.equal(r.ja3.ja3, KNOWN_JA3);
  assert.deepEqual(r.ja3.removed.cipherSuites, [0x1a1a]);
  assert.deepEqual(r.ja3.removed.extensions, [0x1a1a]);
  assert.deepEqual(r.ja3.removed.supportedGroups, [0x1a1a]);
});

test("reordered ciphers give different fingerprint", () => {
  const r = parseClientHello(fixtureBytes("known-reordered"));
  assert.equal(r.ja3.ja3, "771,4866-4865,10-11,29-23,0");
  assert.notEqual(r.ja3.md5, parseClientHello(fixtureBytes("known")).ja3.md5);
});

test("byte-by-byte feed keeps result", () => {
  const input = fixtureBytes("known");
  const whole = parseClientHello(input);
  const bytewise = parseClientHello(input, [1]);
  assert.equal(bytewise.ja3.ja3, whole.ja3.ja3);
  assert.equal(bytewise.ja3.md5, whole.ja3.md5);
  assert.deepEqual(bytewise.cipherSuites, whole.cipherSuites);
});

test("arbitrary chunkings are equivalent", () => {
  const input = fixtureBytes("known");
  const expected = parseClientHello(input).ja3.md5;
  for (const chunks of [[2], [3, 7], [5, 1, 1, 1, 1], [13, 2, 50]]) {
    assert.equal(parseClientHello(input, chunks).ja3.md5, expected);
  }
});

test("ClientHello across two records", () => {
  const r = parseClientHello(fixtureBytes("cross-record"));
  assert.equal(r.ja3.ja3, KNOWN_JA3);
  assert.equal(r.recordCount, 2);
});

test("field source ranges span records", () => {
  const body = buildHelloBody();
  const input = wrapRecords(body, { handshakeSplit: 4 + 37 + 1 });
  const r = parseClientHello(input);
  assert.equal(r.ja3.ja3, KNOWN_JA3);
  assert.equal(r.sources.cipher_suites.inputRanges.length, 2);
});

test("no extensions: body ends after compression methods", () => {
  const r = parseClientHello(fixtureBytes("no-extensions"));
  assert.equal(r.ja3.ja3, "771,4865-4866,,,");
  assert.deepEqual(r.extensions, []);
});

test("unknown extension keeps type and order", () => {
  const r = parseClientHello(fixtureBytes("unknown-extension"));
  assert.equal(r.ja3.ja3, "771,4865-4866,10-40-11,29-23,0");
  const unk = r.extensions.find((e) => e.type === 0x0028);
  assert.ok(unk);
  assert.equal(unk.length, 3);
});

test("extension total length off by one rejected", () => {
  const body = buildHelloBody();
  const extLenOffset = 2 + 32 + 1 + 0 + 2 + 4 + 1 + 1;
  body.writeUInt16BE(body.readUInt16BE(extLenOffset) + 1, extLenOffset);
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_EXT_LEN_MISMATCH");
    return true;
  });
});

test("odd cipher suite bytes rejected", () => {
  const body = buildHelloBody();
  const csLenOffset = 2 + 32 + 1;
  body.writeUInt16BE(3, csLenOffset);
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_ODD_CIPHER_BYTES");
    return true;
  });
});

test("finish with incomplete input is truncated", () => {
  const input = fixtureBytes("known");
  const parser = new ClientHelloParser();
  parser.feed(input.subarray(0, input.length - 2));
  assert.throws(() => parser.finish(), (e: ParseError) => {
    assert.equal(e.code, "E_TRUNCATED");
    return true;
  });
});

test("incomplete record header is truncated", () => {
  const parser = new ClientHelloParser();
  parser.feed(Buffer.from([22, 3, 1]));
  assert.throws(() => parser.finish(), (e: ParseError) => e.code === "E_TRUNCATED");
});

test("non-handshake record type rejected", () => {
  const bad = Buffer.from([23, 3, 1, 0, 1, 0]);
  assert.throws(() => parseClientHello(bad), (e: ParseError) => {
    assert.equal(e.code, "E_BAD_RECORD_TYPE");
    return true;
  });
});

test("first handshake message must be ClientHello", () => {
  const hs = Buffer.alloc(4);
  hs[0] = 2;
  hs.writeUIntBE(0, 1, 3);
  const rec = Buffer.concat([Buffer.from([22, 3, 1, 0, 4]), hs]);
  assert.throws(() => parseClientHello(rec), (e: ParseError) => {
    assert.equal(e.code, "E_BAD_HANDSHAKE_TYPE");
    return true;
  });
});

test("duplicate extension type rejected", () => {
  const body = buildHelloBody({
    extensions: [
      { type: 11, data: Buffer.from([1, 0]) },
      { type: 11, data: Buffer.from([1, 0]) },
    ],
  });
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_DUP_EXTENSION");
    return true;
  });
});

test("session_id over 32 bytes rejected", () => {
  const body = buildHelloBody({ sessionId: Buffer.alloc(33) });
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_SESSION_ID_TOO_LONG");
    return true;
  });
});

test("supported_groups inner length mismatch rejected", () => {
  const body = buildHelloBody({
    extensions: [{ type: 10, data: Buffer.from([0, 99, 0, 29]) }],
  });
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_GROUP_VECTOR_LEN");
    return true;
  });
});

test("tail bytes after first hello not mixed in", () => {
  const r = parseClientHello(fixtureBytes("with-tail"));
  assert.equal(r.ja3.ja3, KNOWN_JA3);
  assert.equal(r.tailBytes, 4);
  const input = fixtureBytes("with-tail");
  assert.equal(r.consumedInputBytes, input.length - 4);
});

test("TLS1.3 style: JA3 version uses legacy_version", () => {
  const body = buildHelloBody({
    legacyVersion: 0x0303,
    extensions: [
      { type: 43, data: Buffer.from([2, 0x03, 0x04]) },
      { type: 10, data: Buffer.from([0, 4, 0, 29, 0, 23]) },
      { type: 11, data: Buffer.from([1, 0]) },
    ],
  });
  const r = parseClientHello(wrapRecords(body));
  assert.equal(r.ja3.ja3, "771,4865-4866,43-10-11,29-23,0");
});

test("empty compression methods rejected", () => {
  const body = buildHelloBody({ compressionMethods: [] });
  assert.throws(() => parseClientHello(wrapRecords(body)), (e: ParseError) => {
    assert.equal(e.code, "E_EMPTY_COMPRESSION");
    return true;
  });
});
