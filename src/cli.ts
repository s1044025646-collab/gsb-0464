import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import { Store } from "./db.js";
import { analyze } from "./service.js";
import { FIXTURES } from "./fixtures.js";
import { startServer } from "./api.js";

const DATA_DIR = process.env.JA3_DATA_DIR ?? path.join(process.cwd(), "data");
const FIXTURES_DIR = path.join(process.cwd(), "fixtures");

function usage(): void {
  console.log(`TLS ClientHello JA3 离线核验工具

用法:
  ja3 parse --hex <hex> [--chunks 1,5,20]     解析十六进制输入
  ja3 parse --file <path> [--chunks ...]      解析二进制文件
  ja3 parse --fixture <name|file.bin>         解析内置/项目夹具
  ja3 fixtures                                生成 fixtures/*.bin 并列出
  ja3 list                                    列出历史分析
  ja3 show <id>                               查看某次分析报告
  ja3 serve [--port N]                        启动 HTTP API（默认空闲端口）

环境变量: JA3_DATA_DIR 指定数据目录（默认 ./data）`);
}

function argValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function parseChunksArg(args: string[]): number[] | undefined {
  const v = argValue(args, "--chunks");
  if (!v) return undefined;
  const parts = v.split(",").map((s) => Number(s.trim()));
  if (parts.some((n) => !Number.isInteger(n) || n <= 0)) {
    console.error("--chunks 必须为正整数，逗号分隔");
    process.exit(2);
  }
  return parts;
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  const store = new Store(DATA_DIR);

  switch (cmd) {
    case "parse": {
      const chunks = parseChunksArg(args);
      let input: Buffer | null = null;
      const hex = argValue(args, "--hex");
      const file = argValue(args, "--file");
      const fixture = argValue(args, "--fixture");
      if (hex) {
        const clean = hex.replace(/\s+/g, "");
        if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
          console.error("hex 非法");
          process.exit(2);
        }
        input = Buffer.from(clean, "hex");
      } else if (file) {
        input = readFileSync(file);
      } else if (fixture) {
        const fx = FIXTURES.find((f) => f.name === fixture);
        input = fx ? fx.build() : readFileSync(path.join(FIXTURES_DIR, fixture));
      } else {
        console.error("需要 --hex / --file / --fixture 之一");
        process.exit(2);
      }
      const result = analyze(store, input, chunks);
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.status === "ok" ? 0 : 1);
      break;
    }
    case "fixtures": {
      mkdirSync(FIXTURES_DIR, { recursive: true });
      for (const f of FIXTURES) {
        const p = path.join(FIXTURES_DIR, `${f.name}.bin`);
        writeFileSync(p, f.build());
        console.log(`${f.name}.bin  ${f.description}`);
      }
      break;
    }
    case "list": {
      console.log(JSON.stringify(store.list(), null, 2));
      break;
    }
    case "show": {
      const id = Number(args[0]);
      if (!Number.isInteger(id)) {
        console.error("需要数字 id");
        process.exit(2);
      }
      const row = store.get(id);
      if (!row) {
        console.error("记录不存在");
        process.exit(1);
      }
      console.log(
        JSON.stringify(
          {
            id: row.id,
            status: row.status,
            sha256: row.sha256,
            ruleVersion: row.rule_version,
            ja3: row.ja3,
            md5: row.md5,
            report: row.report_json ? JSON.parse(row.report_json) : null,
            error: row.error_code ? { code: row.error_code, message: row.error_msg } : null,
          },
          null,
          2
        )
      );
      break;
    }
    case "serve": {
      const portArg = Number(argValue(args, "--port") ?? "0");
      if (!Number.isInteger(portArg) || portArg < 0 || portArg > 65535) {
        console.error("--port 非法");
        process.exit(2);
      }
      if (!existsSync(FIXTURES_DIR)) mkdirSync(FIXTURES_DIR, { recursive: true });
      const { port } = await startServer(store, FIXTURES_DIR, portArg);
      console.log(`API 已启动: http://127.0.0.1:${port}  (数据目录: ${DATA_DIR})`);
      return; // 保持进程
    }
    default:
      usage();
  }
  store.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
