export const LIMITS = {
  MAX_INPUT_BYTES: 1 << 20, // 1 MiB total input
  MAX_RECORD_PAYLOAD: 1 << 14, // 16384, TLS 明文记录上限
  MAX_HANDSHAKE_BODY: 1 << 16, // 64 KiB ClientHello 体上限
} as const;

export const RULE_VERSION = "ja3-subset-1";
