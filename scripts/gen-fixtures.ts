import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { buildClientHello, wrapRecords } from '../src/fixtures.js';

const outDir = join(process.cwd(), 'fixtures');
await mkdir(outDir, { recursive: true });

async function save(name: string, bytes: Buffer): Promise<void> {
  await writeFile(join(outDir, name), bytes);
  console.log(`${name}: ${bytes.length} 字节  ${bytes.subarray(0, Math.min(24, bytes.length)).toString('hex')}...`);
}

const base = buildClientHello({
  version: 0x0303,
  cipherSuites: [4865, 4866],
  supportedGroups: [29, 23],
  ecPointFormats: 0,
});
await save('baseline.bin', wrapRecords(base.bytes));

const withGrease = buildClientHello({
  version: 0x0303,
  cipherSuites: [4865, 4866],
  supportedGroups: [29, 23],
  ecPointFormats: 0,
  greaseCipherAt: 1,
  greaseExtAt: 0,
  greaseGroupAt: 1,
});
await save('with-grease.bin', wrapRecords(withGrease.bytes));

const swapped = buildClientHello({
  version: 0x0303,
  cipherSuites: [4866, 4865],
  supportedGroups: [29, 23],
  ecPointFormats: 0,
});
await save('swapped-ciphers.bin', wrapRecords(swapped.bytes));

const noExt = buildClientHello({ includeExtensions: false });
await save('no-extensions.bin', wrapRecords(noExt.bytes));

const unknownExt = buildClientHello({
  cipherSuites: [4865, 4866],
  supportedGroups: [29, 23],
  unknownExtensions: [{ type: 1234, data: Buffer.from([0xde, 0xad, 0xbe, 0xef]) }],
});
await save('unknown-extension.bin', wrapRecords(unknownExt.bytes));

const cross = buildClientHello({
  version: 0x0303,
  cipherSuites: [4865, 4866],
  supportedGroups: [29, 23],
});
await save('cross-record.bin', wrapRecords(cross.bytes, 0x0301, [7, 19, 60, cross.bytes.length]));

const tls13 = buildClientHello({
  version: 0x0303,
  cipherSuites: [4865, 4866],
  supportedGroups: [29, 23],
  unknownExtensions: [{ type: 43, data: Buffer.from([0x04, 0x03, 0x04]) }],
});
await save('tls13-legacy-0303.bin', wrapRecords(tls13.bytes));

console.log('夹具生成完成');
