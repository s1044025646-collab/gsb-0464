import { Ja3ParseError } from './errors.js';
import { LIMITS } from './limits.js';
import { buildJa3 } from './ja3.js';
import { parseClientHelloBody } from './parseHello.js';
import type { ByteRange, FieldSource, ParseOutcome, RecordInfo } from './types.js';

interface ChunkRef {
  data: Buffer;
  inputStart: number;
}

const CONTENT_TYPE_HANDSHAKE = 22;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1;
const RECORD_HEADER_LEN = 5;
const HANDSHAKE_HEADER_LEN = 4;

type Phase = 'recordHeader' | 'recordPayload' | 'awaitRecordBytes' | 'finished' | 'failed';

export class HelloStreamParser {
  private totalFed = 0;
  private raw: Buffer = Buffer.alloc(0);

  private phase: Phase = 'recordHeader';
  private records: RecordInfo[] = [];

  private currentRecLen = 0;
  private currentRecVersion = 0;
  private currentRecordStart = 0;

  private hsHeaderParts: Buffer[] = [];
  private hsHeaderGot = 0;
  private hsHeaderStartAbs = -1;
  private hsBodyRefs: ChunkRef[] = [];
  private hsBodyGot = 0;
  private hsTotal = 0;
  private hsHeaderAbsOffset = -1;
  private lastRecordTrailing = 0;

  private fatal: Ja3ParseError | null = null;
  private outcome: ParseOutcome | null = null;

  feed(chunk: Buffer): void {
    if (this.phase === 'finished' || this.phase === 'failed') return;
    this.totalFed += chunk.length;
    if (this.totalFed > LIMITS.maxInputBytes) {
      return this.fail(new Ja3ParseError('INPUT_TOO_LARGE', `累计输入超过 ${LIMITS.maxInputBytes} 字节`));
    }
    this.raw = this.raw.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.raw, chunk]);
    this.pump();
  }

  finish(): ParseOutcome {
    if (this.outcome) return this.outcome;
    if (this.fatal) return this.errorOutcome(this.fatal, false);
    if (this.totalFed === 0) {
      return this.errorOutcome(new Ja3ParseError('EMPTY_INPUT', '输入为空'), false);
    }
    if (this.phase !== 'finished') {
      const waiting =
        this.phase === 'recordHeader'
          ? this.raw.length
          : this.hsTotal - HANDSHAKE_HEADER_LEN - this.hsBodyGot;
      return this.errorOutcome(
        new Ja3ParseError('TRUNCATED_INPUT', `finish 时仍缺少字节：未处理 ${this.raw.length}，握手体尚缺 ${Math.max(0, waiting)}`),
        true,
      );
    }
    return this.complete();
  }

  private fail(err: Ja3ParseError): void {
    this.fatal = err;
    this.phase = 'failed';
  }

  private pump(): void {
    while (this.phase !== 'finished' && this.phase !== 'failed') {
      if (this.phase === 'awaitRecordBytes') {
        if (this.raw.length - RECORD_HEADER_LEN < this.currentRecLen) return;
        this.phase = 'recordPayload';
      }
      if (this.phase === 'recordHeader') {
        if (this.raw.length < RECORD_HEADER_LEN) return;
        const recType = this.raw.readUInt8(0);
        if (recType !== CONTENT_TYPE_HANDSHAKE) {
          return this.fail(new Ja3ParseError('UNSUPPORTED_RECORD_TYPE', `记录内容类型 ${recType} 不受支持，仅接受 22(handshake)`));
        }
        this.currentRecVersion = this.raw.readUInt16BE(1);
        this.currentRecLen = this.raw.readUInt16BE(3);
        if (this.currentRecLen > LIMITS.maxRecordPayload) {
          return this.fail(new Ja3ParseError('RECORD_PAYLOAD_TOO_LARGE', `记录载荷长度 ${this.currentRecLen} 超过 ${LIMITS.maxRecordPayload}`));
        }
        this.currentRecordStart = this.totalFed - this.raw.length;
        this.phase = 'recordPayload';
      }

      if (this.phase === 'recordPayload') {
        const available = this.raw.length - RECORD_HEADER_LEN;
        if (available < this.currentRecLen) {
          this.phase = 'awaitRecordBytes';
          return;
        }
        const payloadStart = this.currentRecordStart + RECORD_HEADER_LEN;
        const payloadBase = RECORD_HEADER_LEN;
        const payload = this.raw.subarray(payloadBase, payloadBase + this.currentRecLen);
        this.records.push({
          index: this.records.length,
          recordStart: this.currentRecordStart,
          version: this.currentRecVersion,
          payloadStart,
          payloadLength: this.currentRecLen,
        });
        this.consumePayload(payload, payloadStart);
        if ((this.phase as Phase) === 'failed') return;
      }
    }
  }

  private consumePayload(payload: Buffer, payloadStart: number): void {
    let pos = 0;

    if (this.hsHeaderGot < HANDSHAKE_HEADER_LEN) {
      if (this.hsHeaderGot === 0) this.hsHeaderStartAbs = payloadStart;
      const take = Math.min(payload.length, HANDSHAKE_HEADER_LEN - this.hsHeaderGot);
      this.hsHeaderParts.push(Buffer.from(payload.subarray(0, take)));
      this.hsHeaderGot += take;
      pos = take;

      if (this.hsHeaderGot < HANDSHAKE_HEADER_LEN) {
        this.advanceRecord(pos);
        return;
      }

      const header = Buffer.concat(this.hsHeaderParts);
      const msgType = header.readUInt8(0);
      const bodyLen = (header.readUInt8(1) << 16) | header.readUInt16BE(2);
      if (msgType !== HANDSHAKE_TYPE_CLIENT_HELLO) {
        return this.fail(new Ja3ParseError('NON_CLIENTHELLO_FIRST_MESSAGE', `首条握手消息类型为 ${msgType}，仅接受 ClientHello(1)`));
      }
      if (bodyLen === 0) {
        return this.fail(new Ja3ParseError('BAD_HANDSHAKE_LENGTH', 'ClientHello 握手体长度为 0'));
      }
      if (bodyLen > LIMITS.maxHandshakeBody) {
        return this.fail(new Ja3ParseError('HANDSHAKE_TOO_LARGE', `握手体长度 ${bodyLen} 超过 ${LIMITS.maxHandshakeBody}`));
      }
      this.hsTotal = HANDSHAKE_HEADER_LEN + bodyLen;
      this.hsHeaderAbsOffset = this.hsHeaderStartAbs;
    }

    const need = this.hsTotal - HANDSHAKE_HEADER_LEN - this.hsBodyGot;
    if (need > 0 && pos < payload.length) {
      const take = Math.min(need, payload.length - pos);
      this.hsBodyRefs.push({
        data: Buffer.from(payload.subarray(pos, pos + take)),
        inputStart: payloadStart + pos,
      });
      this.hsBodyGot += take;
      pos += take;
    }

    this.advanceRecord(pos);

    if (this.phase !== 'failed' && this.hsBodyGot === this.hsTotal - HANDSHAKE_HEADER_LEN) {
      this.finishHandshake();
    }
  }

  private advanceRecord(handshakeConsumedInPayload: number): void {
    this.lastRecordTrailing = this.currentRecLen - handshakeConsumedInPayload;
    this.raw = this.raw.subarray(RECORD_HEADER_LEN + this.currentRecLen);
    this.phase = 'recordHeader';
  }

  private finishHandshake(): void {
    const full = Buffer.concat([...this.hsHeaderParts, ...this.hsBodyRefs.map((r) => r.data)]);
    try {
      const fields = parseClientHelloBody(full.subarray(HANDSHAKE_HEADER_LEN));
      const sources: FieldSource[] = fields.sources.map((s) => ({
        field: s.field,
        handshakeOffset: s.handshakeOffset,
        lengthBytes: s.lengthBytes,
        spans: this.mapToAbsolute(s.handshakeOffset, s.lengthBytes),
      }));
      this.parsedFields = { ...fields, sources };
      this.phase = 'finished';
    } catch (err) {
      this.fail(err instanceof Ja3ParseError ? err : new Ja3ParseError('BAD_HANDSHAKE_HEADER', (err as Error).message));
    }
  }

  private parsedFields: ReturnType<typeof parseClientHelloBody> | null = null;

  private mapToAbsolute(bodyOffset: number, len: number): ByteRange[] {
    const relStart = HANDSHAKE_HEADER_LEN + bodyOffset;
    const relEnd = relStart + len;
    const spans: ByteRange[] = [];
    let pos = 0;
    const refs: ChunkRef[] = [
      { data: Buffer.concat(this.hsHeaderParts), inputStart: this.hsHeaderStartAbs },
      ...this.hsBodyRefs,
    ];
    for (const ref of refs) {
      const s = pos;
      const e = pos + ref.data.length;
      const oStart = Math.max(relStart, s);
      const oEnd = Math.min(relEnd, e);
      if (oStart < oEnd) {
        spans.push({
          start: ref.inputStart + (oStart - s),
          endExclusive: ref.inputStart + (oEnd - s),
        });
      }
      pos = e;
    }
    return spans;
  }

  private complete(): ParseOutcome {
    const fields = this.parsedFields!;
    const ja3 = buildJa3(fields);
    const hsEndAbs = this.hsHeaderAbsOffset + this.hsTotal;
    const trailingInRecord = this.lastRecordTrailing;

    this.outcome = {
      ok: true,
      fields,
      ja3,
      records: this.records,
      handshakeHeaderOffset: this.hsHeaderAbsOffset,
      handshakeConsumedBytes: this.hsTotal,
      firstRecordTrailingBytes: trailingInRecord,
      totalInputBytes: this.totalFed,
      bytesConsumed: hsEndAbs,
      truncated: false,
    };
    return this.outcome;
  }

  private errorOutcome(err: Ja3ParseError, truncated: boolean): ParseOutcome {
    this.outcome = {
      ok: false,
      records: this.records,
      handshakeHeaderOffset: this.hsHeaderAbsOffset,
      handshakeConsumedBytes: 0,
      firstRecordTrailingBytes: 0,
      totalInputBytes: this.totalFed,
      bytesConsumed: 0,
      error: { code: err.code, detail: err.detail, handshakeOffset: err.handshakeOffset },
      truncated,
    };
    return this.outcome;
  }
}
