import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as netCreateServer } from 'node:net';
import { join } from 'node:path';
import { parseHex, parseBytes, decodeHex } from './parse.js';
import { Ja3ParseError } from './errors.js';
import { Store } from './store.js';
import { RULE_VERSION } from './limits.js';

export interface ServerHandle {
  server: Server;
  port: number;
  store: Store;
}

function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = netCreateServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (addr && typeof addr === 'object') {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error('无法获取空闲端口')));
      }
    });
  });
}

async function readBody(req: IncomingMessage, maxBytes = 2 * 1024 * 1024): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Ja3ParseError('INPUT_TOO_LARGE', `请求体超过 ${maxBytes} 字节`);
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function json(res: ServerResponse, status: number, obj: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

export async function startApi(port = 0, dataDir = join(process.cwd(), 'data')): Promise<ServerHandle> {
  const store = new Store(join(dataDir, 'ja3.sqlite'));
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { ok: true, ruleVersion: RULE_VERSION });
    }

    if (req.method === 'GET' && url.pathname === '/api/fingerprints') {
      const md5 = url.searchParams.get('md5');
      const id = url.searchParams.get('id');
      if (md5) return json(res, 200, { items: store.findByMd5(md5.toLowerCase()) });
      if (id) {
        const rec = store.get(Number(id));
        if (!rec) return json(res, 404, { error: { code: 'NOT_FOUND', detail: `id=${id}` } });
        return json(res, 200, rec);
      }
      return json(res, 200, { items: store.list(Number(url.searchParams.get('limit') ?? 50)) });
    }

    if (req.method === 'POST' && url.pathname === '/api/parse') {
      try {
        const rawBody = await readBody(req);
        const ct = req.headers['content-type'] ?? '';
        let bytes: Buffer;
        let chunkSize = 0;

        if (ct.includes('application/json')) {
          const parsed = JSON.parse(rawBody.toString('utf8') || '{}') as {
            hex?: string;
            chunkBytes?: number;
          };
          if (typeof parsed.hex !== 'string') {
            return json(res, 400, { error: { code: 'INVALID_REQUEST', detail: '需要 hex 字段' } });
          }
          bytes = decodeHex(parsed.hex);
          chunkSize = Number(parsed.chunkBytes ?? 0);
        } else {
          bytes = rawBody;
          chunkSize = Number(url.searchParams.get('chunkBytes') ?? 0);
        }

        if (chunkSize && (chunkSize < 1 || !Number.isInteger(chunkSize))) {
          return json(res, 400, { error: { code: 'INVALID_REQUEST', detail: 'chunkBytes 必须为正整数' } });
        }

        const outcome = bytes.length === 0 ? parseBytes(Buffer.alloc(0)) : parseBytes(bytes, chunkSize);
        const recordId = store.save(bytes, outcome);
        return json(res, outcome.ok ? 200 : 422, { id: recordId, ruleVersion: RULE_VERSION, ...outcome });
      } catch (err) {
        if (err instanceof Ja3ParseError) {
          return json(res, 400, { error: { code: err.code, detail: err.detail } });
        }
        return json(res, 400, { error: { code: 'INVALID_REQUEST', detail: (err as Error).message } });
      }
    }

    return json(res, 404, { error: { code: 'NOT_FOUND', detail: `${req.method} ${url.pathname}` } });
  });

  const targetPort = port > 0 ? port : await pickFreePort();
  await new Promise<void>((resolve) => server.listen(targetPort, '127.0.0.1', resolve));
  const address = server.address();
  const actualPort = address && typeof address === 'object' ? address.port : targetPort;
  return { server, port: actualPort, store };
}

const invokedMain = process.argv[1] && /server\.(js|ts)$/.test(process.argv[1]);
if (invokedMain) {
  const requested = Number(process.env.PORT ?? process.argv.find((a) => a.startsWith('--port='))?.split('=')[1] ?? 0);
  const dataDir = process.env.DATA_DIR ?? join(process.cwd(), 'data');
  startApi(Number.isFinite(requested) ? requested : 0, dataDir).then(({ port }) => {
    console.log(`JA3 离线解析 API 已启动: http://127.0.0.1:${port}`);
    console.log(`数据目录: ${dataDir}`);
  });
}
