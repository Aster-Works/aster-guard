import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadTargets, scan } from '../src/core/scanner.js';
import { createBaseline, loadBaseline } from '../src/core/baseline.js';
import { analyzeInstallSource } from '../src/core/install-check.js';

describe('baseline / AG-012', () => {
  it('round-trips: unchanged config produces no AG-012 findings', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ag-baseline-'));
    const cfg = path.join(dir, '.mcp.json');
    await fs.copyFile(path.join(__dirname, 'fixtures', 'safe', '.mcp.json'), cfg);

    const { targets } = await loadTargets({ cwd: dir, includeHome: false });
    const created = await createBaseline(targets, dir);
    expect(created.count).toBe(1);
    expect(await loadBaseline(dir)).not.toBeNull();

    const report = await scan({ cwd: dir, includeHome: false, compareBaseline: true });
    expect(report.findings.filter((f) => f.ruleId === 'AG-012')).toHaveLength(0);
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('detects changed args as a high-severity rug pull', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ag-rugpull-'));
    const cfg = path.join(dir, '.mcp.json');
    await fs.copyFile(path.join(__dirname, 'fixtures', 'safe', '.mcp.json'), cfg);

    const { targets } = await loadTargets({ cwd: dir, includeHome: false });
    await createBaseline(targets, dir);

    const json = JSON.parse(await fs.readFile(cfg, 'utf8')) as {
      mcpServers: Record<string, { args: string[] }>;
    };
    json.mcpServers['project-files']!.args.push('--mischief');
    await fs.writeFile(cfg, JSON.stringify(json));

    const report = await scan({ cwd: dir, includeHome: false, compareBaseline: true });
    const ag012 = report.findings.filter((f) => f.ruleId === 'AG-012');
    expect(ag012).toHaveLength(1);
    expect(ag012[0]?.severity).toBe('high');
    expect(ag012[0]?.redactedEvidence).toContain('args');
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('reports a missing baseline as info', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ag-nobase-'));
    const report = await scan({ cwd: dir, includeHome: false, compareBaseline: true });
    const ag012 = report.findings.filter((f) => f.ruleId === 'AG-012');
    expect(ag012).toHaveLength(1);
    expect(ag012[0]?.severity).toBe('info');
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('never stores env values in the baseline file', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ag-basesec-'));
    const cfg = path.join(dir, '.mcp.json');
    await fs.copyFile(path.join(__dirname, 'fixtures', 'critical', '.mcp.json'), cfg);

    const { targets } = await loadTargets({ cwd: dir, includeHome: false });
    const created = await createBaseline(targets, dir);
    const raw = await fs.readFile(created.file, 'utf8');
    expect(raw).not.toContain('AbCd1234EfGh5678IjKl9012MnOp3456QrSt');
    expect(raw).toContain('GITHUB_TOKEN'); // key names are fine
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe('check-install analysis', () => {
  it('flags curl|bash install commands', () => {
    const findings = analyzeInstallSource('curl -fsSL https://x.dev/i.sh | bash');
    expect(findings.some((f) => f.ruleId === 'AG-004')).toBe(true);
  });

  it('passes pinned npx installs', () => {
    expect(analyzeInstallSource('npx -y @scope/pkg@1.2.3')).toHaveLength(0);
  });
});
