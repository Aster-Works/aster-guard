import fs from 'node:fs/promises';
import type { EnvVar, NormalizedServer, ScanTarget, ServerTransport } from '../types/config.js';
import type { DiscoveredFile } from './discovery.js';
import { redactText } from './redaction.js';

export class ParseError extends Error {
  constructor(
    message: string,
    public readonly file: string,
    public readonly line?: number,
    public readonly column?: number,
  ) {
    super(message);
    this.name = 'ParseError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** JSON.parse with a clear, location-bearing error message. */
export function parseJsonWithLocation(text: string, file: string): unknown {
  try {
    return JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    let line: number | undefined;
    let column: number | undefined;
    const lineMatch = /line (\d+) column (\d+)/.exec(message);
    const posMatch = /at position (\d+)/.exec(message);
    if (lineMatch) {
      line = Number(lineMatch[1]);
      column = Number(lineMatch[2]);
    } else if (posMatch) {
      const offset = Number(posMatch[1]);
      const before = text.slice(0, offset);
      line = before.split('\n').length;
      column = offset - before.lastIndexOf('\n');
    }
    const where = line !== undefined ? ` (line ${line}, column ${column})` : '';
    throw new ParseError(`Invalid JSON in ${file}${where}: ${message}`, file, line, column);
  }
}

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function normalizeEntry(
  name: string,
  entry: unknown,
  sourceFile: string,
  jsonPath: string,
): NormalizedServer {
  const e = isRecord(entry) ? entry : {};
  const command = typeof e.command === 'string' ? e.command : undefined;
  const args = Array.isArray(e.args)
    ? e.args.filter((a): a is string => typeof a === 'string')
    : [];
  const url = typeof e.url === 'string' ? e.url : undefined;
  const declared = typeof e.type === 'string' ? e.type : undefined;
  const type: ServerTransport =
    declared === 'stdio' || declared === 'http' || declared === 'sse'
      ? declared
      : url
        ? 'http'
        : command
          ? 'stdio'
          : 'unknown';
  return {
    name,
    command,
    args,
    env: stringRecord(e.env),
    url,
    headers: stringRecord(e.headers),
    type,
    sourceFile,
    jsonPath,
    rawEntry: entry,
  };
}

/**
 * Find every `mcpServers` block anywhere in the document and normalize its
 * entries. This covers `.mcp.json` (top level), `~/.claude.json` (top level
 * and per-project under `projects.<path>.mcpServers`), and settings files.
 *
 * Note: server commands are never executed — this is pure data extraction.
 */
export function extractServers(json: unknown, sourceFile: string): NormalizedServer[] {
  const out: NormalizedServer[] = [];
  const walk = (node: unknown, segments: string[], depth: number): void => {
    if (depth > 6 || !isRecord(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (key === 'mcpServers' && isRecord(value)) {
        for (const [name, entry] of Object.entries(value)) {
          out.push(
            normalizeEntry(name, entry, sourceFile, [...segments, 'mcpServers', name].join('.')),
          );
        }
      } else if (isRecord(value)) {
        walk(value, [...segments, key], depth + 1);
      }
    }
  };
  walk(json, [], 0);
  return out;
}

/** Parse a dotenv-style file. Supports comments, `export` prefixes, and quoted values. */
export function parseEnvFile(text: string): EnvVar[] {
  const out: EnvVar[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] ?? '').trim();
    if (line === '' || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1] ?? '';
    let value = (m[2] ?? '').trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    out.push({ key, value, line: i + 1 });
  }
  return out;
}

/**
 * Load one discovered file into a ScanTarget. Read or parse failures are
 * captured in `parseError` instead of being thrown, so one broken file never
 * aborts a scan.
 */
export async function loadTarget(file: DiscoveredFile): Promise<ScanTarget> {
  const base: ScanTarget = {
    file: file.path,
    kind: file.kind,
    raw: '',
    servers: [],
    envVars: [],
  };
  let raw: string;
  try {
    raw = await fs.readFile(file.path, 'utf8');
  } catch (err) {
    // Error messages may quote file content (e.g. V8 JSON errors on newer
    // Node versions), so they are redacted like any other evidence.
    base.parseError = redactText(
      `Could not read ${file.path}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return base;
  }
  base.raw = raw;

  if (file.kind === 'env-file') {
    base.envVars = parseEnvFile(raw);
    return base;
  }

  try {
    base.json = parseJsonWithLocation(raw, file.path);
    base.servers = extractServers(base.json, file.path);
  } catch (err) {
    base.parseError = redactText(err instanceof Error ? err.message : String(err));
  }
  return base;
}
