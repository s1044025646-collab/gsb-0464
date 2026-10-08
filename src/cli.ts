#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { parseHex, parseBytes, decodeHex } from './parse.js';
import { Ja3ParseError } from './errors.js';
import { Store } from './store.js';
import { RULE_VERSION } from './limits.js';

function usage(): string {
  return [
    '用法: ja3cli <命令> [选项]',
    '',
    '命令:',
    '  parse --hex <十六进制> [--chunk <字节>] [--db <路径>]',
    '  parse --file <二进制夹具> [--chunk <字节>] [--db <路径>]',
    '  report --id <记录ID> [--out <文件>] [--db <路径>]',
    '  query --md5 <JA3 MD5> | --id <记录ID> [--db <路径>]',
    '  list [--limit N] [--db <路径>]',
    '',
    '--chunk 指定按固定字节数逐块 feed（用于验证分块无关性）',
    '--db 默认为 ./data/ja3.sqlite',
  ].join('\n');
}

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  if (i >= 0) return args[i + 1];
  const inline = args.find((a) => a.startsWith(`--${name}=`));
  return inline?.slice(name.length + 3);
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h') {
    console.log(usage());
    return 0;
  }

  const dbPath = resolve(arg(rest, 'db') ?? join(process.cwd(), 'data', 'ja3.sqlite'));
  const store = new Store(dbPath);

  try {
    if (cmd === 'parse') {
      const hex = arg(rest, 'hex');
      const file = arg(rest, 'file');
      const chunk = Number(arg(rest, 'chunk') ?? 0);
      if (!hex && !file) throw new Ja3ParseError('INVALID_HEX', '必须提供 --hex 或 --file');
      if (chunk && (chunk < 1 || !Number.isInteger(chunk))) throw new Ja3ParseError('INVALID_HEX', '--chunk 必须为正整数');
      const bytes = hex !== undefined ? decodeHex(hex) : await readFile(resolve(file!));
      const outcome = parseBytes(bytes, chunk);
      const id = store.save(bytes, outcome);
      console.log(JSON.stringify({ id, ruleVersion: RULE_VERSION, ...outcome }, null, 2));
      if (!outcome.ok) return 2;
      return 0;
    }

    if (cmd === 'query') {
      const md5 = arg(rest, 'md5');
      const id = arg(rest, 'id');
      if (md5) {
        console.log(JSON.stringify({ items: store.findByMd5(md5.toLowerCase()) }, null, 2));
      } else if (id) {
        const rec = store.get(Number(id));
        if (!rec) {
          console.error(`未找到记录 id=${id}`);
          return 3;
        }
        console.log(JSON.stringify(rec, null, 2));
      } else {
        throw new Ja3ParseError('INVALID_HEX', 'query 需要 --md5 或 --id');
      }
      return 0;
    }

    if (cmd === 'list') {
      const limit = Number(arg(rest, 'limit') ?? 50);
      console.log(JSON.stringify({ items: store.list(limit) }, null, 2));
      return 0;
    }

    if (cmd === 'report') {
      const id = arg(rest, 'id');
      if (!id) throw new Ja3ParseError('INVALID_HEX', 'report 需要 --id');
      const rec = store.get(Number(id));
      if (!rec) {
        console.error(`未找到记录 id=${id}`);
        return 3;
      }
      const report = {
        id: rec.id,
        createdAt: rec.created_at,
        ruleVersion: rec.rule_version,
        status: rec.status,
        inputSha256: rec.input_sha256,
        inputLength: rec.input_length,
        ja3Text: rec.ja3_text,
        ja3Md5: rec.ja3_md5,
        errorCode: rec.error_code,
        errorDetail: rec.error_detail,
        truncated: Boolean(rec.truncated),
        recordsCount: rec.records_count,
        trailingBytes: rec.trailing_bytes,
        parse: JSON.parse(rec.report),
      };
      const out = arg(rest, 'out');
      const text = JSON.stringify(report, null, 2);
      if (out) {
        const outPath = resolve(out);
        await mkdir(dirname(outPath), { recursive: true });
        await writeFile(outPath, text, 'utf8');
        console.log(`报告已导出: ${outPath}`);
      } else {
        console.log(text);
      }
      return 0;
    }

    console.error(usage());
    return 1;
  } catch (err) {
    if (err instanceof Ja3ParseError) {
      console.error(JSON.stringify({ ok: false, error: { code: err.code, detail: err.detail } }, null, 2));
      return 2;
    }
    throw err;
  } finally {
    store.close();
  }
}

main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
  console.error(err);
  process.exit(1);
});
