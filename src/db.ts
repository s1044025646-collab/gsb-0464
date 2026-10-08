import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { RULE_VERSION } from "./limits.js";

export interface AnalysisRow {
  id: number;
  created_at: string;
  status: "ok" | "error";
  sha256: string;
  bytes: Buffer;
  chunk_desc: string;
  rule_version: string;
  ja3: string | null;
  md5: string | null;
  report_json: string | null;
  error_code: string | null;
  error_msg: string | null;
}

export class Store {
  private db: DatabaseSync;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.db = new DatabaseSync(path.join(dataDir, "ja3.sqlite"));
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        status TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        bytes BLOB NOT NULL,
        chunk_desc TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        ja3 TEXT,
        md5 TEXT,
        report_json TEXT,
        error_code TEXT,
        error_msg TEXT
      )
    `);
  }

  saveOk(input: Buffer, chunkDesc: string, report: object, ja3: string, md5: string): number {
    const stmt = this.db.prepare(
      `INSERT INTO analyses (created_at, status, sha256, bytes, chunk_desc, rule_version, ja3, md5, report_json)
       VALUES (?, 'ok', ?, ?, ?, ?, ?, ?, ?)`
    );
    const r = stmt.run(
      new Date().toISOString(),
      createHash("sha256").update(input).digest("hex"),
      input,
      chunkDesc,
      RULE_VERSION,
      ja3,
      md5,
      JSON.stringify(report)
    );
    return Number(r.lastInsertRowid);
  }

  saveError(input: Buffer, chunkDesc: string, code: string, msg: string): number {
    const stmt = this.db.prepare(
      `INSERT INTO analyses (created_at, status, sha256, bytes, chunk_desc, rule_version, error_code, error_msg)
       VALUES (?, 'error', ?, ?, ?, ?, ?, ?)`
    );
    const r = stmt.run(
      new Date().toISOString(),
      createHash("sha256").update(input).digest("hex"),
      input,
      chunkDesc,
      RULE_VERSION,
      code,
      msg
    );
    return Number(r.lastInsertRowid);
  }

  list(limit = 50): Omit<AnalysisRow, "bytes" | "report_json">[] {
    return this.db
      .prepare(
        `SELECT id, created_at, status, sha256, chunk_desc, rule_version, ja3, md5, error_code, error_msg
         FROM analyses ORDER BY id DESC LIMIT ?`
      )
      .all(limit) as never;
  }

  get(id: number): AnalysisRow | undefined {
    return this.db.prepare(`SELECT * FROM analyses WHERE id = ?`).get(id) as never;
  }

  close(): void {
    this.db.close();
  }
}
