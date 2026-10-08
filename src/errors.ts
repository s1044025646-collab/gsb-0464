export type ErrorCode =
  | "E_EMPTY_INPUT"
  | "E_INPUT_TOO_LARGE"
  | "E_RECORD_TOO_LARGE"
  | "E_HANDSHAKE_TOO_LARGE"
  | "E_BAD_RECORD_TYPE"
  | "E_BAD_HANDSHAKE_TYPE"
  | "E_TRUNCATED"
  | "E_BODY_UNDERFLOW"
  | "E_SESSION_ID_TOO_LONG"
  | "E_ODD_CIPHER_BYTES"
  | "E_EMPTY_CIPHER_SUITES"
  | "E_EMPTY_COMPRESSION"
  | "E_EXT_LEN_MISMATCH"
  | "E_DUP_EXTENSION"
  | "E_GROUP_VECTOR_LEN"
  | "E_POINT_FORMAT_VECTOR_LEN"
  | "E_BAD_ARGS";

export class ParseError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
    public readonly offset?: number
  ) {
    super(message);
    this.name = "ParseError";
  }
}
