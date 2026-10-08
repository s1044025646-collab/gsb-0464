export const LIMITS = {
  maxInputBytes: 1024 * 1024,
  maxRecordPayload: 16384 + 256,
  maxHandshakeBody: 16384 + 256,
  maxSessionId: 32,
  randomLength: 32,
  maxCipherSuitesBytes: 65534,
  maxCompressionMethods: 255,
  maxExtensionPayload: 65535,
  maxGroups: 32767,
  maxEcPointFormats: 255,
} as const;

export const RULE_VERSION = 'ja3-classic-1';
