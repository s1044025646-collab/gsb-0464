import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseBytes, parseHex } from '../src/parse.js';
import { Store } from '../src/store.js';

const dataDir = join(process.cwd(), 'data');
const store = new Store(join(dataDir, 'ja3.sqlite'));

function show(label: string, bytes: Buffer, chunk = 0): void {
  const r = parseBytes(bytes, chunk);
  const id = store.save(bytes, r);
  console.log(`\n=== ${label}${chunk ? `（每块 ${chunk} 字节 feed）` : ''} ===`);
  if (r.ok) {
    console.log(`id=${id}  JA3=${r.ja3!.text}`);
    console.log(`MD5=${r.ja3!.md5}  记录数=${r.records.length}  同记录尾部=${r.firstRecordTrailingBytes}`);
  } else {
    console.log(`id=${id}  失败: ${r.error!.code} ${r.error!.detail ?? ''} truncated=${r.truncated}`);
  }
}

for (const name of ['baseline.bin', 'with-grease.bin', 'swapped-ciphers.bin', 'no-extensions.bin', 'unknown-extension.bin', 'cross-record.bin', 'tls13-legacy-0303.bin']) {
  const bytes = await readFile(join(process.cwd(), 'fixtures', name));
  show(name, bytes);
}

const baseline = await readFile(join(process.cwd(), 'fixtures', 'baseline.bin'));
show('baseline 逐字节 feed', baseline, 1);
show('baseline 每 3 字节 feed', baseline, 3);

const truncated = baseline.subarray(0, baseline.length - 5);
show('末尾截断 5 字节', truncated);

const badType = Buffer.from(baseline);
badType[0] = 23;
show('不支持的记录类型 23', badType);

const odd = parseHex('');
void odd;

console.log('\n按 MD5 查询 baseline:');
const baseResult = parseBytes(baseline);
console.log(store.findByMd5(baseResult.ja3!.md5).map((r) => ({ id: r.id, status: r.status, ja3: r.ja3_text })));

store.close();
