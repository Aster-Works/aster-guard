import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hasBlockingFindings, scan } from '../src/core/scanner.js';

const fixture = (name: string) => path.join(__dirname, 'fixtures', name, '.mcp.json');

describe('scan end-to-end', () => {
  it('gives the safe fixture a clean A', async () => {
    const report = await scan({ file: fixture('safe') });
    expect(report.findings).toHaveLength(0);
    expect(report.riskScore).toBe(100);
    expect(report.grade).toBe('A');
    expect(hasBlockingFindings(report)).toBe(false);
  });

  it('flags the risky fixture and blocks', async () => {
    const report = await scan({ file: fixture('risky') });
    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    expect(ruleIds.has('AG-003')).toBe(true);
    expect(ruleIds.has('AG-006')).toBe(true);
    expect(ruleIds.has('AG-007')).toBe(true);
    expect(report.grade).not.toBe('A');
    expect(hasBlockingFindings(report)).toBe(true);
  });

  it('gives the critical fixture an F and redacts the token everywhere', async () => {
    const report = await scan({ file: fixture('critical') });
    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    for (const expected of ['AG-001', 'AG-002', 'AG-003', 'AG-004', 'AG-005', 'AG-010', 'AG-011']) {
      expect(ruleIds.has(expected), `missing ${expected}`).toBe(true);
    }
    expect(report.grade).toBe('F');
    expect(JSON.stringify(report)).not.toContain('AbCd1234EfGh5678IjKl9012MnOp3456QrSt');
  });

  it('scans .env files without panicking the score', async () => {
    const report = await scan({ file: path.join(__dirname, 'fixtures', 'risky', '.env') });
    const envFindings = report.findings.filter((f) => f.ruleId === 'AG-005');
    expect(envFindings).toHaveLength(1);
    expect(envFindings[0]?.severity).toBe('info');
    expect(JSON.stringify(report)).not.toContain('sk-FakeFixture1234567890abcdefXYZ');
  });

  it('throws a clear error for missing files', async () => {
    await expect(scan({ file: '/no/such/file.json' })).rejects.toThrow('File not found');
  });

  it('reports unparseable files as findings instead of crashing', async () => {
    const os = await import('node:os');
    const fs = await import('node:fs/promises');
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aster-guard-broken-'));
    const file = path.join(dir, '.mcp.json');
    await fs.writeFile(file, '{not json');
    const report = await scan({ file });
    expect(report.findings.some((f) => f.ruleId === 'AG-000')).toBe(true);
    await fs.rm(dir, { recursive: true, force: true });
  });
});
