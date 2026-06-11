import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hostMatches, initPolicy, loadPolicy } from '../src/core/policy.js';
import { scan } from '../src/core/scanner.js';
import { extractServers } from '../src/core/parser.js';
import { AG007 } from '../src/rules/AG007-unknown-remote.js';
import type { ScanTarget } from '../src/types/config.js';

async function tmpDir(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function writePolicy(dir: string, policy: unknown): Promise<void> {
  await fs.mkdir(path.join(dir, '.aster-guard'), { recursive: true });
  await fs.writeFile(path.join(dir, '.aster-guard', 'policy.json'), JSON.stringify(policy));
}

describe('loadPolicy', () => {
  it('returns an empty policy when no file exists', async () => {
    const dir = await tmpDir('ag-pol-none-');
    expect(await loadPolicy(dir)).toEqual({ policy: {} });
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('loads a valid policy', async () => {
    const dir = await tmpDir('ag-pol-ok-');
    await writePolicy(dir, { allowedRemoteHosts: ['*.corp.dev'], failOn: 'medium' });
    const { policy, error } = await loadPolicy(dir);
    expect(error).toBeUndefined();
    expect(policy.allowedRemoteHosts).toEqual(['*.corp.dev']);
    expect(policy.failOn).toBe('medium');
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('reports unknown keys and bad JSON without applying anything', async () => {
    const dir = await tmpDir('ag-pol-bad-');
    await writePolicy(dir, { allowedHosts: ['x'] }); // typo key
    const typo = await loadPolicy(dir);
    expect(typo.error).toContain('allowedHosts');
    expect(typo.policy).toEqual({});

    await fs.writeFile(path.join(dir, '.aster-guard', 'policy.json'), '{broken');
    const broken = await loadPolicy(dir);
    expect(broken.error).toBeDefined();
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe('hostMatches', () => {
  it('matches exact hosts and wildcards case-insensitively', () => {
    expect(hostMatches('mcp.corp.dev', ['*.corp.dev'])).toBe(true);
    expect(hostMatches('MCP.CORP.DEV', ['*.corp.dev'])).toBe(true);
    expect(hostMatches('corp.dev', ['*.corp.dev'])).toBe(false); // wildcard needs a subdomain
    expect(hostMatches('mcp.corp.dev', ['mcp.corp.dev'])).toBe(true);
    expect(hostMatches('evil.dev', ['*.corp.dev', 'good.dev'])).toBe(false);
    expect(hostMatches('any.dev', undefined)).toBe(false);
  });
});

describe('AG-007 with allowlist', () => {
  const target = (url: string): ScanTarget => {
    const json = { mcpServers: { remote: { url } } };
    return {
      file: '/t/.mcp.json',
      kind: 'mcp-config',
      raw: '',
      json,
      servers: extractServers(json, '/t/.mcp.json'),
      envVars: [],
    };
  };

  it('skips allowlisted hosts and still flags others', () => {
    const ctx = { policy: { allowedRemoteHosts: ['*.corp.dev'] } };
    expect(AG007.check(target('https://mcp.corp.dev/sse'), ctx)).toHaveLength(0);
    expect(AG007.check(target('https://mcp.unknown.dev/sse'), ctx)).toHaveLength(1);
    expect(AG007.check(target('https://mcp.corp.dev/sse'))).toHaveLength(1); // no policy
  });
});

describe('scan with policy', () => {
  it('suppresses ignoreRules findings end-to-end', async () => {
    const dir = await tmpDir('ag-pol-scan-');
    await fs.copyFile(
      path.join(__dirname, 'fixtures', 'critical', '.mcp.json'),
      path.join(dir, '.mcp.json'),
    );
    await writePolicy(dir, { ignoreRules: ['ag005', 'AG-001'] });
    const report = await scan({ cwd: dir, includeHome: false });
    const ids = new Set(report.findings.map((f) => f.ruleId));
    expect(ids.has('AG-005')).toBe(false);
    expect(ids.has('AG-001')).toBe(false);
    expect(ids.has('AG-010')).toBe(true); // others remain
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('surfaces an invalid policy as a low finding', async () => {
    const dir = await tmpDir('ag-pol-err-');
    await writePolicy(dir, { failOn: 'sometimes' });
    const report = await scan({ cwd: dir, includeHome: false });
    const finding = report.findings.find((f) => f.title === 'Invalid policy file');
    expect(finding?.severity).toBe('low');
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe('initPolicy', () => {
  it('creates a template once and never overwrites', async () => {
    const dir = await tmpDir('ag-pol-init-');
    const first = await initPolicy(dir);
    expect(first.created).toBe(true);
    await fs.writeFile(first.file, '{"ignoreRules":["AG-008"]}');
    const second = await initPolicy(dir);
    expect(second.created).toBe(false);
    expect(await fs.readFile(first.file, 'utf8')).toContain('AG-008'); // untouched
    await fs.rm(dir, { recursive: true, force: true });
  });
});
