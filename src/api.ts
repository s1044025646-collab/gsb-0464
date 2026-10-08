import http from "node:http";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { Store } from "./db.js";
import { analyze } from "./service.js";
import { FIXTURES, getFixture } from "./fixtures.js";
import { LIMITS, RULE_VERSION } from "./limits.js";

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(data);
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > LIMITS.MAX_INPUT_BYTES * 4) {
        reject(new Error("请求体过大"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseChunks(v: unknown): number[] | undefined {
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v) || v.some((n) => !Number.isInteger(n) || n <= 0)) {
    throw Object.assign(new Error("chunks 必须为正整数数组"), { code: "E_BAD_ARGS" });
  }
  return v as number[];
}

export function createServer(store: Store, fixturesDir: string): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "GET" && url.pathname === "/api/health") {
        return sendJson(res, 200, { ok: true, ruleVersion: RULE_VERSION });
      }
      if (req.method === "GET" && url.pathname === "/api/fixtures") {
        return sendJson(res, 200, {
          builtin: FIXTURES.map((f) => ({ name: f.name, description: f.description })),
          files: existsSync(fixturesDir)
            ? readdirSync(fixturesDir).filter((f) => f.endsWith(".bin"))
            : [],
        });
      }
      if (req.method === "POST" && url.pathname === "/api/parse") {
        const raw = await readBody(req);
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(raw.toString("utf8"));
        } catch {
          return sendJson(res, 400, { error: { code: "E_BAD_ARGS", message: "请求体必须是 JSON" } });
        }
        let input: Buffer | null = null;
        if (typeof body.hex === "string") {
          const hex = body.hex.replace(/\s+/g, "");
          if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 || hex.length === 0) {
            return sendJson(res, 400, {
              error: { code: "E_BAD_ARGS", message: "hex 必须是偶数长度的十六进制字符串" },
            });
          }
          input = Buffer.from(hex, "hex");
        } else if (typeof body.fixture === "string") {
          const fx = getFixture(body.fixture);
          if (fx) {
            input = fx.build();
          } else {
            const p = path.join(fixturesDir, body.fixture);
            if (!p.startsWith(path.resolve(fixturesDir)) || !existsSync(p)) {
              return sendJson(res, 404, {
                error: { code: "E_BAD_ARGS", message: `夹具不存在: ${body.fixture}` },
              });
            }
            input = readFileSync(p);
          }
        }
        if (!input) {
          return sendJson(res, 400, {
            error: { code: "E_BAD_ARGS", message: "必须提供 hex 或 fixture 之一" },
          });
        }
        let chunks: number[] | undefined;
        try {
          chunks = parseChunks(body.chunks);
        } catch {
          return sendJson(res, 400, {
            error: { code: "E_BAD_ARGS", message: "chunks 必须为正整数数组" },
          });
        }
        const result = analyze(store, input, chunks);
        return sendJson(res, result.status === "ok" ? 200 : 422, result);
      }
      if (req.method === "GET" && url.pathname === "/api/analyses") {
        return sendJson(res, 200, store.list());
      }
      const m = url.pathname.match(/^\/api\/analyses\/(\d+)(\/report)?$/);
      if (req.method === "GET" && m) {
        const row = store.get(Number(m[1]));
        if (!row) {
          return sendJson(res, 404, { error: { code: "E_NOT_FOUND", message: "记录不存在" } });
        }
        if (m[2] === "/report") {
          return sendJson(res, 200, {
            id: row.id,
            status: row.status,
            sha256: row.sha256,
            ruleVersion: row.rule_version,
            ja3: row.ja3,
            md5: row.md5,
            report: row.report_json ? JSON.parse(row.report_json) : null,
            error: row.error_code ? { code: row.error_code, message: row.error_msg } : null,
          });
        }
        return sendJson(res, 200, { ...row, bytes: undefined, report_json: undefined });
      }
      sendJson(res, 404, { error: { code: "E_NOT_FOUND", message: "未知路由" } });
    } catch (err) {
      sendJson(res, 500, {
        error: { code: "E_INTERNAL", message: err instanceof Error ? err.message : String(err) },
      });
    }
  });
}

export function startServer(
  store: Store,
  fixturesDir: string,
  port: number
): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer(store, fixturesDir);
    server.on("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, port: typeof addr === "object" && addr ? addr.port : port });
    });
  });
}
