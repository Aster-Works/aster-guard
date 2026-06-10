import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import fg from 'fast-glob';
import type { ScanTargetKind } from '../types/config.js';

export interface DiscoveredFile {
  path: string;
  kind: ScanTargetKind;
}

const PROJECT_FILES: ReadonlyArray<{ rel: string; kind: ScanTargetKind }> = [
  { rel: '.mcp.json', kind: 'mcp-config' },
  { rel: '.cursor/mcp.json', kind: 'mcp-config' },
  { rel: '.vscode/mcp.json', kind: 'mcp-config' },
  { rel: '.claude/settings.json', kind: 'claude-settings' },
  { rel: '.claude/settings.local.json', kind: 'claude-settings' },
  { rel: '.env', kind: 'env-file' },
  { rel: '.env.local', kind: 'env-file' },
  { rel: '.env.development', kind: 'env-file' },
  { rel: '.env.production', kind: 'env-file' },
];

const HOME_FILES: ReadonlyArray<{ rel: string; kind: ScanTargetKind }> = [
  { rel: '.claude.json', kind: 'mcp-config' },
  { rel: '.claude/settings.json', kind: 'claude-settings' },
  { rel: '.cursor/mcp.json', kind: 'mcp-config' },
  { rel: '.codeium/windsurf/mcp_config.json', kind: 'mcp-config' },
  { rel: '.gemini/settings.json', kind: 'mcp-config' },
  {
    // Cline on macOS
    rel: 'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
    kind: 'mcp-config',
  },
];

/**
 * Discover supported configuration files. Missing files are silently skipped;
 * scanning never fails because a file does not exist.
 */
export async function discoverFiles(cwd: string, includeHome: boolean): Promise<DiscoveredFile[]> {
  const found: DiscoveredFile[] = [];

  const matches = new Set(
    await fg(
      PROJECT_FILES.map((f) => f.rel),
      { cwd, dot: true, absolute: true, onlyFiles: true, suppressErrors: true },
    ),
  );
  for (const f of PROJECT_FILES) {
    const abs = path.resolve(cwd, f.rel);
    // fast-glob returns POSIX-style paths; normalize before comparing.
    if (matches.has(abs) || matches.has(abs.split(path.sep).join('/'))) {
      found.push({ path: abs, kind: f.kind });
    }
  }

  if (includeHome) {
    for (const f of HOME_FILES) {
      const abs = path.join(os.homedir(), f.rel);
      if (fs.existsSync(abs) && !found.some((d) => d.path === abs)) {
        found.push({ path: abs, kind: f.kind });
      }
    }
  }

  return found;
}

/** Infer the target kind for an explicitly given file path. */
export function kindForPath(filePath: string): ScanTargetKind {
  const base = path.basename(filePath);
  if (base === '.env' || base.startsWith('.env.')) return 'env-file';
  if (base.startsWith('settings') && filePath.includes('.claude')) return 'claude-settings';
  return 'mcp-config';
}
