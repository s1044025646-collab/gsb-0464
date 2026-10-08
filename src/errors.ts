export type Ja3ErrorCode =
  | 'TRUNCATED_INPUT'
  | 'UNSUPPORTED_RECORD_TYPE'
  | 'UNSUPPORTED_RECORD_VERSION'
  | 'RECORD_PAYLOAD_TOO_LARGE'
  | 'HANDSHAKE_TOO_LARGE'
  | 'INPUT_TOO_LARGE'
  | 'NON_CLIENTHELLO_FIRST_MESSAGE'
  | 'BAD_HANDSHAKE_HEADER'
  | 'BAD_HANDSHAKE_LENGTH'
  | 'BAD_SESSION_ID'
  | 'BAD_CIPHER_SUITES'
  | 'BAD_COMPRESSION_METHODS'
  | 'BAD_EXTENSIONS_LENGTH'
  | 'DUPLICATE_EXTENSION'
  | 'BAD_EXTENSION_LENGTH'
  | 'BAD_SUPPORTED_GROUPS'
  | 'BAD_EC_POINT_FORMATS'
  | 'INVALID_HEX'
  | 'EMPTY_INPUT';

export class Ja3ParseError extends Error {
  readonly code: Ja3ErrorCode;
  readonly detail?: string;
  readonly handshakeOffset?: number;

  constructor(code: Ja3ErrorCode, detail?: string, handshakeOffset?: number) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'Ja3ParseError';
    this.code = code;
    this.detail = detail;
    this.handshakeOffset = handshakeOffset;
  }
}
