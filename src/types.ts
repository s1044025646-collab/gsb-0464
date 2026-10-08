export interface ByteRange {
  start: number;
  endExclusive: number;
}

export interface FieldSource {
  field: string;
  handshakeOffset: number;
  lengthBytes: number;
  spans: ByteRange[];
}

export interface ExtensionInfo {
  type: number;
  dataLength: number;
  handshakeOffset: number;
}

export interface ClientHelloFields {
  legacyVersion: number;
  randomHex: string;
  sessionIdHex: string;
  cipherSuites: number[];
  compressionMethods: number[];
  extensions: ExtensionInfo[];
  supportedGroups: number[];
  ecPointFormats: number[];
  sources: FieldSource[];
  handshakeBodyLength: number;
}

export interface Ja3Result {
  raw: {
    version: number;
    cipherSuites: number[];
    extensionTypes: number[];
    supportedGroups: number[];
    ecPointFormats: number[];
  };
  removed: {
    cipherSuites: number[];
    extensionTypes: number[];
    supportedGroups: number[];
  };
  text: string;
  md5: string;
}

export interface RecordInfo {
  index: number;
  recordStart: number;
  version: number;
  payloadStart: number;
  payloadLength: number;
}

export interface ParseOutcome {
  ok: boolean;
  fields?: ClientHelloFields;
  ja3?: Ja3Result;
  records: RecordInfo[];
  handshakeHeaderOffset: number;
  handshakeConsumedBytes: number;
  firstRecordTrailingBytes: number;
  totalInputBytes: number;
  bytesConsumed: number;
  error?: { code: string; detail?: string; handshakeOffset?: number };
  truncated: boolean;
}
