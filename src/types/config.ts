export type ServerTransport = 'stdio' | 'http' | 'sse' | 'unknown';

/** One MCP server entry normalized into a common shape, regardless of source file format. */
export interface NormalizedServer {
  name: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  type: ServerTransport;
  sourceFile: string;
  /** Dotted JSON path of this entry inside the source file, e.g. "mcpServers.github". */
  jsonPath: string;
  /** The raw parsed entry, for rules that inspect non-standard fields (descriptions etc.). */
  rawEntry: unknown;
}

export type ScanTargetKind = 'mcp-config' | 'claude-settings' | 'env-file';

export interface EnvVar {
  key: string;
  value: string;
  line: number;
}

/** A single file loaded for scanning. */
export interface ScanTarget {
  /** Absolute path. */
  file: string;
  kind: ScanTargetKind;
  raw: string;
  json?: unknown;
  servers: NormalizedServer[];
  envVars: EnvVar[];
  /** Human-readable message when the file could not be read or parsed. */
  parseError?: string;
}
