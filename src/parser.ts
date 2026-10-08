import { ParseError } from "./errors.js";
import { LIMITS } from "./limits.js";
import { buildJa3, isGrease, Ja3Result } from "./ja3.js";

export interface ByteRange {
  start: number;
  end: number; // 开区间，相对整个输入字节流
}

export interface FieldSource {
  hsOffset: number; // 相对握手体（ClientHello body）起点
  length: number;
  inputRanges: ByteRange[]; // 跨记录时为多段
}

export interface ExtensionInfo {
  type: number;
  length: number;
  source: FieldSource;
}

export interface HelloReport {
  ok: true;
  ruleVersion: string;
  legacyVersion: number;
  randomHex: string;
  sessionIdHex: string;
  cipherSuites: number[];
  compressionMethods: number[];
  extensions: ExtensionInfo[];
  supportedGroups: number[];
  ecPointFormats: number[];
  ja3: Ja3Result;
  consumedInputBytes: number; // 首个 Hello 消费掉的输入字节（含记录头）
  tailBytes: number; // 首个 Hello 之后仍未消费的输入字节
  recordCount: number;
  sources: Record<string, FieldSource>;
}

interface Segment {
  hsStart: number; // 握手流偏移
  inputStart: number; // 输入流偏移
  length: number;
}

type State = "records" | "done";

export class ClientHelloParser {
  private state: State = "records";
  private recordBuf: Buffer = Buffer.alloc(0);
  private hsBuf: Buffer = Buffer.alloc(0); // 握手层字节流（记录载荷拼接）
  private segments: Segment[] = [];
  private inputOffset = 0; // 已接收的输入字节总数
  private recordCount = 0;
  private totalFed = 0;
  private report: HelloReport | null = null;
  private consumedInput = 0;

  feed(chunk: Buffer): void {
    if (this.state === "done") {
      // 首个 Hello 已完成，剩余字节只计入尾部，不再解析
      this.totalFed += chunk.length;
      if (this.totalFed > LIMITS.MAX_INPUT_BYTES) {
        throw new ParseError("E_INPUT_TOO_LARGE", "输入超过大小限制");
      }
      return;
    }
    this.totalFed += chunk.length;
    if (this.totalFed > LIMITS.MAX_INPUT_BYTES) {
      throw new ParseError("E_INPUT_TOO_LARGE", "输入超过大小限制");
    }
    this.recordBuf = Buffer.concat([this.recordBuf, chunk]);
    this.processRecords();
  }

  finish(): HelloReport {
    if (this.state === "done" && this.report) return this.report;
    if (this.totalFed === 0) {
      throw new ParseError("E_EMPTY_INPUT", "输入为空");
    }
    throw new ParseError(
      "E_TRUNCATED",
      "finish 时仍存在不完整的记录头、记录载荷或握手消息",
      this.inputOffset
    );
  }

  private processRecords(): void {
    for (;;) {
      if (this.recordBuf.length < 5) return;
      const contentType = this.recordBuf[0];
      const recordLen = this.recordBuf.readUInt16BE(3);
      if (contentType !== 22) {
        throw new ParseError(
          "E_BAD_RECORD_TYPE",
          `不支持的记录内容类型 ${contentType}，仅接受 22(handshake)`,
          this.inputOffset
        );
      }
      if (recordLen > LIMITS.MAX_RECORD_PAYLOAD) {
        throw new ParseError(
          "E_RECORD_TOO_LARGE",
          `记录载荷 ${recordLen} 超过上限 ${LIMITS.MAX_RECORD_PAYLOAD}`,
          this.inputOffset
        );
      }
      if (this.recordBuf.length < 5 + recordLen) return; // 等更多数据
      const payload = this.recordBuf.subarray(5, 5 + recordLen);
      const payloadInputStart = this.inputOffset + 5;
      this.recordBuf = this.recordBuf.subarray(5 + recordLen);
      this.inputOffset += 5 + recordLen;
      this.recordCount++;

      const hsStart = this.hsBuf.length;
      this.hsBuf = Buffer.concat([this.hsBuf, payload]);
      this.segments.push({ hsStart, inputStart: payloadInputStart, length: recordLen });

      this.tryParseHandshake();
      if (this.state === "done") {
        // 剩余 recordBuf 属于尾部
        this.inputOffset += this.recordBuf.length;
        this.recordBuf = Buffer.alloc(0);
        return;
      }
    }
  }

  private tryParseHandshake(): void {
    if (this.hsBuf.length < 4) return;
    const msgType = this.hsBuf[0];
    const bodyLen = this.hsBuf.readUIntBE(1, 3);
    if (msgType !== 1) {
      throw new ParseError(
        "E_BAD_HANDSHAKE_TYPE",
        `首个握手消息类型为 ${msgType}，仅接受 1(ClientHello)`,
        this.inputOffset
      );
    }
    if (bodyLen > LIMITS.MAX_HANDSHAKE_BODY) {
      throw new ParseError(
        "E_HANDSHAKE_TOO_LARGE",
        `握手体 ${bodyLen} 超过上限 ${LIMITS.MAX_HANDSHAKE_BODY}`,
        this.inputOffset
      );
    }
    if (this.hsBuf.length < 4 + bodyLen) return; // 等更多记录

    const body = this.hsBuf.subarray(4, 4 + bodyLen);
    const bodyHsOffset = 4;
    const report = this.parseClientHello(body, bodyHsOffset);
    // 消费范围：握手消息最后一个字节所在的输入位置
    const endRanges = this.mapRange(bodyHsOffset + bodyLen - 1, 1);
    this.consumedInput = endRanges[0].end;
    report.consumedInputBytes = this.consumedInput;
    report.recordCount = this.recordCount;
    this.report = report;
    this.state = "done";
  }

  private mapRange(hsOffset: number, length: number): ByteRange[] {
    const ranges: ByteRange[] = [];
    let remaining = length;
    let pos = hsOffset;
    for (const seg of this.segments) {
      const segEnd = seg.hsStart + seg.length;
      if (pos >= segEnd) continue;
      if (pos + remaining <= seg.hsStart) break;
      const take = Math.min(remaining, segEnd - pos);
      if (take > 0 && pos >= seg.hsStart) {
        ranges.push({
          start: seg.inputStart + (pos - seg.hsStart),
          end: seg.inputStart + (pos - seg.hsStart) + take,
        });
        remaining -= take;
        pos += take;
        if (remaining === 0) break;
      }
    }
    return ranges;
  }

  private field(hsOffset: number, length: number): FieldSource {
    return { hsOffset, length, inputRanges: this.mapRange(hsOffset, length) };
  }

  private parseClientHello(body: Buffer, bodyHsOffset: number): HelloReport {
    const sources: Record<string, FieldSource> = {};
    let pos = 0;
    const need = (n: number, what: string): void => {
      if (pos + n > body.length) {
        throw new ParseError(
          "E_BODY_UNDERFLOW",
          `握手体在解析 ${what} 时提前结束（需要 ${n} 字节，偏移 ${pos}）`
        );
      }
    };
    const src = (offset: number, len: number): FieldSource =>
      this.field(bodyHsOffset + offset, len);

    need(2, "legacy_version");
    const legacyVersion = body.readUInt16BE(pos);
    sources.legacy_version = src(pos, 2);
    pos += 2;

    need(32, "random");
    const randomHex = body.subarray(pos, pos + 32).toString("hex");
    sources.random = src(pos, 32);
    pos += 32;

    need(1, "session_id 长度");
    const sessionIdLen = body[pos];
    sources.session_id_length = src(pos, 1);
    pos += 1;
    if (sessionIdLen > 32) {
      throw new ParseError("E_SESSION_ID_TOO_LONG", `session_id 长度 ${sessionIdLen} 超过 32`);
    }
    need(sessionIdLen, "session_id");
    const sessionIdHex = body.subarray(pos, pos + sessionIdLen).toString("hex");
    sources.session_id = src(pos, sessionIdLen);
    pos += sessionIdLen;

    need(2, "cipher_suites 长度");
    const cipherBytes = body.readUInt16BE(pos);
    sources.cipher_suites_length = src(pos, 2);
    pos += 2;
    if (cipherBytes === 0) {
      throw new ParseError("E_EMPTY_CIPHER_SUITES", "cipher_suites 不能为空");
    }
    if (cipherBytes % 2 !== 0) {
      throw new ParseError("E_ODD_CIPHER_BYTES", `cipher_suites 字节数 ${cipherBytes} 不是偶数`);
    }
    need(cipherBytes, "cipher_suites");
    const cipherSuites: number[] = [];
    for (let i = 0; i < cipherBytes; i += 2) {
      cipherSuites.push(body.readUInt16BE(pos + i));
    }
    sources.cipher_suites = src(pos, cipherBytes);
    pos += cipherBytes;

    need(1, "compression_methods 长度");
    const compLen = body[pos];
    sources.compression_methods_length = src(pos, 1);
    pos += 1;
    if (compLen === 0) {
      throw new ParseError("E_EMPTY_COMPRESSION", "compression_methods 不能为空");
    }
    need(compLen, "compression_methods");
    const compressionMethods: number[] = [];
    for (let i = 0; i < compLen; i++) compressionMethods.push(body[pos + i]);
    sources.compression_methods = src(pos, compLen);
    pos += compLen;

    const extensions: ExtensionInfo[] = [];
    const supportedGroups: number[] = [];
    const ecPointFormats: number[] = [];

    if (pos < body.length) {
      need(2, "extensions 总长度");
      const extTotal = body.readUInt16BE(pos);
      sources.extensions_length = src(pos, 2);
      pos += 2;
      if (pos + extTotal !== body.length) {
        throw new ParseError(
          "E_EXT_LEN_MISMATCH",
          `扩展总长度 ${extTotal} 与剩余握手体 ${body.length - pos} 不一致`
        );
      }
      const seen = new Set<number>();
      const extEnd = pos + extTotal;
      while (pos < extEnd) {
        if (pos + 4 > extEnd) {
          throw new ParseError("E_EXT_LEN_MISMATCH", "扩展头跨越扩展块边界");
        }
        const extType = body.readUInt16BE(pos);
        const extLen = body.readUInt16BE(pos + 2);
        const extHeaderOffset = pos;
        pos += 4;
        if (pos + extLen > extEnd) {
          throw new ParseError(
            "E_EXT_LEN_MISMATCH",
            `扩展 ${extType} 声明长度 ${extLen} 超出扩展块边界`
          );
        }
        if (seen.has(extType)) {
          throw new ParseError("E_DUP_EXTENSION", `重复的扩展类型 ${extType}`);
        }
        seen.add(extType);
        const dataStart = pos;
        const data = body.subarray(pos, pos + extLen);
        pos += extLen;
        extensions.push({
          type: extType,
          length: extLen,
          source: src(extHeaderOffset, 4 + extLen),
        });

        if (extType === 10) {
          if (extLen < 2 || data.readUInt16BE(0) !== extLen - 2) {
            throw new ParseError("E_GROUP_VECTOR_LEN", "supported_groups 内部长度不匹配");
          }
          if ((extLen - 2) % 2 !== 0) {
            throw new ParseError("E_GROUP_VECTOR_LEN", "supported_groups 元素宽度必须为 2");
          }
          for (let i = 2; i + 2 <= extLen; i += 2) {
            supportedGroups.push(data.readUInt16BE(i));
          }
          sources.supported_groups = src(dataStart, extLen);
        } else if (extType === 11) {
          if (extLen < 1 || data[0] !== extLen - 1) {
            throw new ParseError(
              "E_POINT_FORMAT_VECTOR_LEN",
              "ec_point_formats 内部长度不匹配"
            );
          }
          for (let i = 1; i < extLen; i++) ecPointFormats.push(data[i]);
          sources.ec_point_formats = src(dataStart, extLen);
        }
      }
    }

    const ja3 = buildJa3({
      version: legacyVersion,
      cipherSuites,
      extensions: extensions.map((e) => e.type),
      supportedGroups,
      ecPointFormats,
      removed: {
        cipherSuites: cipherSuites.filter(isGrease),
        extensions: extensions.map((e) => e.type).filter(isGrease),
        supportedGroups: supportedGroups.filter(isGrease),
      },
    });

    return {
      ok: true,
      ruleVersion: "ja3-subset-1",
      legacyVersion,
      randomHex,
      sessionIdHex,
      cipherSuites,
      compressionMethods,
      extensions,
      supportedGroups,
      ecPointFormats,
      ja3,
      consumedInputBytes: 0,
      tailBytes: 0,
      recordCount: 0,
      sources,
    };
  }
}

export function parseClientHello(
  input: Buffer,
  chunkSizes?: number[]
): HelloReport {
  const parser = new ClientHelloParser();
  if (!chunkSizes || chunkSizes.length === 0) {
    parser.feed(input);
  } else {
    let offset = 0;
    for (const size of chunkSizes) {
      if (size <= 0) throw new ParseError("E_BAD_ARGS", "分块大小必须为正整数");
      if (offset >= input.length) break;
      parser.feed(input.subarray(offset, Math.min(offset + size, input.length)));
      offset += size;
    }
    if (offset < input.length) parser.feed(input.subarray(offset));
  }
  const report = parser.finish();
  report.tailBytes = input.length - report.consumedInputBytes;
  return report;
}
