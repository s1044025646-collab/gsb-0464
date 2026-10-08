import { createHash } from 'node:crypto';
import { isGrease } from './grease.js';
import type { ClientHelloFields, Ja3Result } from './types.js';

export function buildJa3(fields: ClientHelloFields): Ja3Result {
  const removedCs: number[] = [];
  const removedExt: number[] = [];
  const removedGroups: number[] = [];

  const cipherSuites = fields.cipherSuites.filter((v) => {
    const g = isGrease(v);
    if (g) removedCs.push(v);
    return !g;
  });
  const extensionTypes = fields.extensions
    .map((e) => e.type)
    .filter((v) => {
      const g = isGrease(v);
      if (g) removedExt.push(v);
      return !g;
    });
  const supportedGroups = fields.supportedGroups.filter((v) => {
    const g = isGrease(v);
    if (g) removedGroups.push(v);
    return !g;
  });

  const parts = [
    String(fields.legacyVersion),
    cipherSuites.join('-'),
    extensionTypes.join('-'),
    supportedGroups.join('-'),
    fields.ecPointFormats.join('-'),
  ];
  const text = parts.join(',');
  const md5 = createHash('md5').update(text, 'utf8').digest('hex');

  return {
    raw: {
      version: fields.legacyVersion,
      cipherSuites: [...fields.cipherSuites],
      extensionTypes: fields.extensions.map((e) => e.type),
      supportedGroups: [...fields.supportedGroups],
      ecPointFormats: [...fields.ecPointFormats],
    },
    removed: {
      cipherSuites: removedCs,
      extensionTypes: removedExt,
      supportedGroups: removedGroups,
    },
    text,
    md5,
  };
}
