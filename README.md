# TLS ClientHello 分片解析与 JA3 指纹核验（离线后端）

纯本地、离线的 TLS ClientHello 检查服务。输入人工构造的 TLS 记录字节流，
提取第一个明文 ClientHello 的版本、密码套件与扩展列表，生成经典 JA3 原始
字符串与 MD5 摘要。只处理调用者给出的字节：不抓网卡、不连接服务器、
不解密流量，也不做证书签发或网络握手。

技术栈：TypeScript + Node.js（>= 22，使用内置 `node:sqlite` 与 `node:crypto`），
无第三方运行时依赖，不需要 Docker / WSL / 外部在线 API。

## 快速开始

```powershell
npm install
npm run build        # 编译 TypeScript 到 dist/
npm test             # 构建并运行全部测试（node:test）
npm run cli fixtures # 生成 fixtures/*.bin 手工夹具
npm start            # 启动 API（默认选择空闲端口，127.0.0.1）
```

演示：

```powershell
# CLI 解析内置夹具，按逐字节分块 feed
node dist/src/cli.js parse --fixture known --chunks 1
# 解析十六进制输入
node dist/src/cli.js parse --hex "160301..." --chunks 5,7
# 查看历史与报告（数据在 ./data/ja3.sqlite，重启仍可核对原字节）
node dist/src/cli.js list
node dist/src/cli.js show 1
```

## 解析子集（明确范围）

- 只接受内容类型 22（handshake）的明文 TLS 记录；其他记录类型报
  `E_BAD_RECORD_TYPE`。
- 自行解析 5 字节记录头与 4 字节握手头，多字节长度一律网络大端序。
- 记录内可以只有握手消息的一部分；一个 ClientHello 可跨多条记录。
  先按记录边界取载荷，再累计完整握手消息，绝不把每条记录当作完整 Hello。
- 支持按任意字节块逐块 `feed`；只有 `finish` 时才把剩余不完整头/载荷
  判定为截断（`E_TRUNCATED`）。
- 首个握手消息必须是 ClientHello（类型 1），否则 `E_BAD_HANDSHAKE_TYPE`。
- 解析字段：`legacy_version`、32 字节 `random`、单字节长度的 `session_id`
  （最长 32）、双字节长度的 `cipher_suites`（字节数必须为正偶数）、
  单字节长度的 `compression_methods`（不能为空）。
- 握手体可恰好在压缩方法后结束（无扩展）；否则扩展总长度必须精确覆盖
  剩余握手体（`E_EXT_LEN_MISMATCH`）。
- 解释扩展 10（supported_groups，双字节长度向量）与 11
  （ec_point_formats，单字节长度向量），校验元素宽度与内部长度；
  其他扩展只保留类型与原顺序；重复扩展类型报 `E_DUP_EXTENSION`。
- TLS 1.3 样例中 JA3 版本字段仍取 `legacy_version`，不取记录版本或
  `supported_versions` 最大值。

## JA3 规则（rule version: `ja3-subset-1`）

五段十进制字段，逗号连接，列表内用短横线，空列表保留空段：

```
版本,密码套件,扩展类型,supported_groups,ec_point_formats
```

- 仅从密码套件、扩展类型、groups 中剔除 16 个 GREASE 值
  （0x0a0a、0x1a1a … 0xfafa）；不排序、不去重普通套件；
  8 位 point format 不当 GREASE 处理。
- 报告同时输出原始字段、被剔除项与最终文本，便于独立复算 MD5。
- 已知样例原文 `771,4865-4866,10-11,29-23,0`，MD5
  `8150a3a1f3293b354572405efc20ad75`（已用 PowerShell 独立复算核对）。
- 指纹仅用于离线核验，不用于宣称唯一识别真实客户端。

## 未消费尾部策略

只对完整且合法的首个 Hello 发布指纹。若首个 Hello 之后同一记录或后续
字节仍有剩余，报告 `consumedInputBytes` 与 `tailBytes`，尾部字节不混入
首个 Hello 的字段与指纹，也不再按记录解析。

## 字段来源

每个字段记录其相对握手体的偏移（`hsOffset`）与长度；跨记录时
`inputRanges` 给出原输入字节流中的多段区间列表。

## 大小限制

- 输入总字节：1 MiB（`E_INPUT_TOO_LARGE`）
- 单条记录载荷：16384 字节（`E_RECORD_TOO_LARGE`）
- 握手体：64 KiB（`E_HANDSHAKE_TOO_LARGE`）

所有长度先校验再读取，坏长度不会触发无界分配。

## HTTP API

`npm start` 或 `node dist/src/cli.js serve --port 8080`（不传端口则选空闲端口）。

- `GET  /api/health` — 服务与规则版本
- `GET  /api/fixtures` — 内置夹具与 fixtures/ 目录文件
- `POST /api/parse` — 体：`{"hex": "..."} ` 或 `{"fixture": "known"}`，
  可选 `"chunks": [1,5,20]`；成功 200，解析失败 422 并带错误码
- `GET  /api/analyses` — 历史列表
- `GET  /api/analyses/:id` 与 `/api/analyses/:id/report` — 查询指纹与完整报告

## SQLite 存储

`data/ja3.sqlite`（可用环境变量 `JA3_DATA_DIR` 改目录）。每次分析插入新行：
原字节 BLOB、SHA-256 摘要、分块方式、规则版本、成功时的 JA3/MD5/报告 JSON
或失败时的错误码与诊断。错误报告不覆盖旧记录，重启后仍可核对原字节。

## 错误码

`E_EMPTY_INPUT` `E_INPUT_TOO_LARGE` `E_RECORD_TOO_LARGE`
`E_HANDSHAKE_TOO_LARGE` `E_BAD_RECORD_TYPE` `E_BAD_HANDSHAKE_TYPE`
`E_TRUNCATED` `E_BODY_UNDERFLOW` `E_SESSION_ID_TOO_LONG`
`E_ODD_CIPHER_BYTES` `E_EMPTY_CIPHER_SUITES` `E_EMPTY_COMPRESSION`
`E_EXT_LEN_MISMATCH` `E_DUP_EXTENSION` `E_GROUP_VECTOR_LEN`
`E_POINT_FORMAT_VECTOR_LEN` `E_BAD_ARGS`

## 测试

`npm test` 覆盖：逐字节 feed、跨记录头、跨握手体、无扩展、未知扩展、
扩展长度差一、奇数套件字节、finish 截断、GREASE 等价、套件换序、
重复扩展、尾部字节、TLS 1.3 legacy_version 语义、任意分块结果不变。
夹具为手工字节布局（`src/fixtures.ts`），MD5 可用系统工具独立核对。
