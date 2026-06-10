import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { discoverFiles, kindForPath } from '../src/core/discovery.js';

let dir: string;

beforeAll(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aster-guard-test-'));
  await fs.writeFile(path.join(dir, '.mcp.json'), '{"mcpServers":{}}');
  await fs.writeFile(path.join(dir, '.env.local'), 'FOO=bar\n');
  await fs.mkdir(path.join(dir, '.claude'));
  await fs.writeFile(path.join(dir, '.claude', 'settings.json'), '{}');
});

afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

describe('discoverFiles', () => {
  it('finds supported files with the right kinds', async () => {
    const found = await discoverFiles(dir, false);
    const byName = new Map(found.map((f) => [path.relative(dir, f.path), f.kind]));
    expect(byName.get('.mcp.json')).toBe('mcp-config');
    expect(byName.get('.env.local')).toBe('env-file');
    expect(byName.get(path.join('.claude', 'settings.json'))).toBe('claude-settings');
    expect(found).toHaveLength(3);
  });

  it('returns an empty list for a directory without configs', async () => {
    const empty = await fs.mkdtemp(path.join(os.tmpdir(), 'aster-guard-empty-'));
    expect(await discoverFiles(empty, false)).toHaveLength(0);
    await fs.rm(empty, { recursive: true, force: true });
  });
});

describe('kindForPath', () => {
  it('classifies explicit paths', () => {
    expect(kindForPath('/x/.env.production')).toBe('env-file');
    expect(kindForPath('/x/.claude/settings.local.json')).toBe('claude-settings');
    expect(kindForPath('/x/.mcp.json')).toBe('mcp-config');
  });
});
