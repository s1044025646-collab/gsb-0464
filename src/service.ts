import { parseClientHello } from "./parser.js";
import { ParseError } from "./errors.js";
import { Store } from "./db.js";

export interface AnalyzeResult {
  id: number;
  status: "ok" | "error";
  report?: unknown;
  error?: { code: string; message: string };
}

export function analyze(
  store: Store,
  input: Buffer,
  chunkSizes?: number[]
): AnalyzeResult {
  const chunkDesc =
    chunkSizes && chunkSizes.length > 0 ? `chunks:${chunkSizes.join(",")}` : "whole";
  try {
    const report = parseClientHello(input, chunkSizes);
    const id = store.saveOk(input, chunkDesc, report, report.ja3.ja3, report.ja3.md5);
    return { id, status: "ok", report };
  } catch (err) {
    if (err instanceof ParseError) {
      const id = store.saveError(input, chunkDesc, err.code, err.message);
      return { id, status: "error", error: { code: err.code, message: err.message } };
    }
    throw err;
  }
}
