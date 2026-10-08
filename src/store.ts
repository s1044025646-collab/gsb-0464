import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { RULE_VERSION } from './limits.js';
import type { ParseOutcome } from './types.js';

export interface StoredRecord {
  id: number;
  created_at: string;
  input_sha256: string;
  input_length: number;
  bytes_hex: string;
  rule_version: string;
  status: 'ok' | 'failed';
  ja3_text: string | null;
  ja3_md5: string | null;
  error_code: string | null;
  error_detail: string | null;
  truncated: number;
  records_count: number;
  trailing_bytes: number;
  report: string;
}

export class Store {
  private db: DatabaseSync;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS parses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        input_length INTEGER NOT NULL,
        bytes_hex TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        status TEXT NOT NULL,
        ja3_text TEXT,
        ja3_md5 TEXT,
        error_code TEXT,
        error_detail TEXT,
        truncated INTEGER NOT NULL DEFAULT 0,
        records_count INTEGER NOT NULL DEFAULT 0,
        trailing_bytes INTEGER NOT NULL DEFAULT 0,
        report TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_parses_md5 ON parses(ja3_md5);
      CREATE INDEX IF NOT EXISTS idx_parses_status ON parses(status);
    `);
  }

  save(input: Buffer, outcome: ParseOutcome): number {
    const sha = createHash('sha256').update(input).digest('hex');
    const stmt = this.db.prepare(`
      INSERT INTO parses (
        created_at, input_sha256, input_length, bytes_hex, rule_version,
        status, ja3_text, ja3_md5, error_code, error_detail,
        truncated, records_count, trailing_bytes, report
      ) VALUES (
        :created_at, :sha, :len, :hex, :rule,
        :status, :ja3text, :md5, :code, :detail,
        :trunc, :rcount, :trail, :report
      )
    `);
    const result = stmt.run({
      created_at: new Date().toISOString(),
      sha,
      len: input.length,
      hex: input.toString('hex'),
      rule: RULE_VERSION,
      status: outcome.ok ? 'ok' : 'failed',
      ja3text: outcome.ja3?.text ?? null,
      md5: outcome.ja3?.md5 ?? null,
      code: outcome.error?.code ?? null,
      detail: outcome.error?.detail ?? null,
      trunc: outcome.truncated ? 1 : 0,
      rcount: outcome.records.length,
      trail: outcome.firstRecordTrailingBytes,
      report: JSON.stringify(outcome),
    });
    return Number(result.lastInsertRowid);
  }

  get(id: number): StoredRecord | undefined {
    return this.db.prepare('SELECT * FROM parses WHERE id = ?').get(id) as unknown as StoredRecord | undefined;
  }

  findByMd5(md5: string): StoredRecord[] {
    return this.db.prepare('SELECT * FROM parses WHERE ja3_md5 = ? ORDER BY id').all(md5) as unknown as StoredRecord[];
  }

  list(limit = 50): StoredRecord[] {
    return this.db.prepare('SELECT * FROM parses ORDER BY id DESC LIMIT ?').all(limit) as unknown as StoredRecord[];
  }

  close(): void {
    this.db.close();
  }
}
