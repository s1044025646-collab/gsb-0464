# TLS ClientHello 分片解析与 JA3 指纹核验（离线后端）

只做后端的**离线** TLS ClientHello 检查服务：输入人工构造的 TLS 记录字节流，
自行解析记录层与握手层边界，提取第一个明文 ClientHello 的版本、密码套件与扩展，
生成经典 JA3 五段字符串与 MD5 摘要，并把原字节摘要、固定副本、规则版本与
成功/失败诊断持久化到 SQLite。

**本服务明确不做**：抓网卡、连接服务器、解密流量、证书签发、网络握手。
指纹不用于宣称唯一识别真实客户端，仅用于对给定字节的可复算核验。

## 支持子集

- 仅接受内容类型 `22 (handshake)` 的明文 TLS 记录，五字节记录头：
  `type(1)=22 | version(2，仅记录不参与 JA3) | length(2，大端)`。
- 四字节握手头：`type(1) | length(3，大端 24 位)`。首条握手消息必须是
  `ClientHello(type=1)`，否则返回 `NON_CLIENTHELLO_FIRST_MESSAGE`。
- 一个 ClientHello 可跨任意多条记录，握手头也可跨记录；先按记录边界取载荷，
  再累计握手消息，绝不把每条记录当成完整 Hello。
- 调用方可按任意字节块逐块 `feed`；只有在 `finish` 时才把剩余不完整头/载荷
  认定为 `TRUNCATED_INPUT`。
- ClientHello 字段：`legacy_version(2)`、`random(32)`、`session_id(1+长度, ≤32)`、
  `cipher_suites(2+向量)`、`compression_methods(1+向量)`。
  - 密码套件字节数必须为正偶数，否则 `BAD_CIPHER_SUITES`。
  - 压缩方法向量不能为空，否则 `BAD_COMPRESSION_METHODS`。
- 扩展：握手体可恰好在 compression_methods 后结束（无扩展）；否则
  `extensions_length(2)` 必须精确覆盖剩余握手体，偏差报 `BAD_EXTENSIONS_LENGTH`。
  每个扩展 `type(2)+length(2)+data`，声明范围越界报 `BAD_EXTENSION_LENGTH`；
  **重复扩展类型直接拒绝**（`DUPLICATE_EXTENSION`）。未知扩展不解释内容，
  但保留类型与原顺序。
- 解释扩展 `10 supported_groups`（双字节长度向量，元素宽 2 字节；内部长度不一致
  报 `BAD_SUPPORTED_GROUPS`）与 `11 ec_point_formats`（单字节长度向量，
  非空；内部长度不一致报 `BAD_EC_POINT_FORMATS`）。
- JA3 版本字段始终取 Hello 内 `legacy_version`，**不**取记录版本，也不取
  `supported_versions(43)` 中的版本（该扩展作为未知扩展保留类型）。
- 每个字段记录相对握手体的偏移；跨记录来源以绝对输入字节区间 `spans` 列表返回。

## JA3 构造规则

五段十进制，逗号连接：

```
legacy_version,cipher_suites,extension_types,supported_groups,ec_point_formats
```

- 列表内部用 `-`；空列表保留空段（无扩展样例：`771,4865-4866,,,`）。
- 仅从**密码套件、扩展类型、groups** 移除 16 个 GREASE 值
  `0x0a0a, 0x1a1a, …, 0xfafa`（低字节为 `0x0a` 且两字节相等）。
- 不排序、不去重普通套件；八位 ec_point_format（如 `0`）不参与 GREASE 判断。
- MD5 用 Node 内置 `crypto` 计算，解析与字符串拼接全部自行实现；
  返回 `raw`（原始字段）、`removed`（剔除项）、`text`、`md5`，便于独立复算。

已知基准：版本 `771`、套件 `[4865,4866]`、扩展 `[10,11]`、groups `[29,23]`、
point formats `[0]`：

```
771,4865-4866,10-11,29-23,0
```

## 未消费尾部策略

- 仅对完整且合法的**首个** ClientHello 发布指纹。
- 若该 Hello 结束时所在记录还有剩余字节，返回
  `firstRecordTrailingBytes`（同记录尾部长度）与 `bytesConsumed`
  （首个 Hello 含记录头共消费的绝对字节数），尾部字节不混入 Hello，也不继续解析。
- 更后面的记录不做解析；如需第二消息应另行调用。

## 限制与错误码

`src/limits.ts` 中限制：总输入 1 MiB、单记录载荷 16640、握手体 16640、
session_id ≤ 32、套件向量 ≤ 65534 字节等；坏长度在读取前校验，不触发无界分配。

错误码（`src/errors.ts`）：`TRUNCATED_INPUT`、`UNSUPPORTED_RECORD_TYPE`、
`RECORD_PAYLOAD_TOO_LARGE`、`HANDSHAKE_TOO_LARGE`、`INPUT_TOO_LARGE`、
`NON_CLIENTHELLO_FIRST_MESSAGE`、`BAD_HANDSHAKE_LENGTH`、`BAD_SESSION_ID`、
`BAD_CIPHER_SUITES`、`BAD_COMPRESSION_METHODS`、`BAD_EXTENSIONS_LENGTH`、
`DUPLICATE_EXTENSION`、`BAD_EXTENSION_LENGTH`、`BAD_SUPPORTED_GROUPS`、
`BAD_EC_POINT_FORMATS`、`INVALID_HEX`、`EMPTY_INPUT`。
失败诊断与成功记录一样写入 SQLite（`status='failed'`），只追加、不覆盖旧记录，
重启后仍可按原字节 SHA-256 与固定十六进制副本核对。

## 环境要求

- Windows 本地运行；Node.js ≥ 22（开发于 v25，使用内置 `node:sqlite`），
  无需 Docker、WSL、付费服务或外部在线 API，唯一网络面是本机 HTTP API。

## 构建 / 测试 / 演示

```powershell
npm install
npm run gen-fixtures   # 生成 fixtures/*.bin 手工字节夹具
npm test               # node:test，19 项用例
npm run build          # tsc -> dist/
npm run demo           # 解析全部夹具、逐字节 feed、截断/坏类型演示
```

CLI：

```powershell
node dist/src/cli.js parse --file fixtures/baseline.bin --chunk 7
node dist/src/cli.js parse --hex 1603010041... --chunk 1
node dist/src/cli.js query --md5 8150a3a1f3293b354572405efc20ad75
node dist/src/cli.js query --id 1
node dist/src/cli.js report --id 1 --out data/report-1.json
node dist/src/cli.js list --limit 20
```

`--chunk N` 按固定 N 字节逐块 feed，用于验证分块方式不改变字段与摘要。
解析失败时 CLI 退出码为 `2`，记录不存在为 `3`。

HTTP API（默认自动选择空闲端口；`PORT` 或 `--port=`、`DATA_DIR` 可覆盖，
数据默认写入项目内 `data/ja3.sqlite`）：

```powershell
npm start
# POST /api/parse   Content-Type: application/json  {"hex":"...","chunkBytes":1}
#                   或直接 POST 原始二进制（?chunkBytes=N）
# GET  /api/fingerprints?md5=<hex>   ?id=<n>   ?limit=50
# GET  /health
```

成功返回 `200`；字节合法但 Hello 校验失败返回 `422`（同样落库）；
请求格式错误返回 `400`。

## 独立复算 MD5（PowerShell）

```powershell
$s = '771,4865-4866,10-11,29-23,0'
[BitConverter]::ToString(
  [Security.Cryptography.MD5]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($s))
).Replace('-','').ToLower()
# 8150a3a1f3293b354572405efc20ad75
```

## 目录

- `src/stream.ts` 记录层/握手层流式重组（支持任意分块 feed）
- `src/parseHello.ts` ClientHello 握手体字段与边界校验
- `src/ja3.ts` GREASE 剔除、五段字符串与 MD5
- `src/fixtures.ts` 手工字节布局构造器（测试与夹具生成共用）
- `src/store.ts` SQLite 持久化（`node:sqlite`）
- `src/server.ts` / `src/cli.ts` HTTP API 与命令行
- `test/parser.test.ts` 19 项测试；`scripts/` 夹具生成与演示
