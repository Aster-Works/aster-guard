import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scan } from '../src/core/scanner.js';
import {
  renderJson,
  renderMarkdown,
  renderPlainSummary,
  renderSarif,
  renderTerminal,
} from '../src/core/report.js';

const critical = path.join(__dirname, 'fixtures', 'critical', '.mcp.json');
const RAW_TOKEN = 'AbCd1234EfGh5678IjKl9012MnOp3456QrSt';

describe('report rendering', () => {
  it('renders a Japanese terminal report', async () => {
    const report = await scan({ file: critical });
    const out = renderTerminal(report, 'ja');
    expect(out).toContain('Aster Guard MCP セキュリティレポート');
    expect(out).toContain('リスクスコア');
    expect(out).toContain('AG-005');
    expect(out).not.toContain(RAW_TOKEN);
  });

  it('renders an English terminal report', async () => {
    const report = await scan({ file: critical });
    const out = renderTerminal(report, 'en');
    expect(out).toContain('Risk Score');
    expect(out).not.toContain(RAW_TOKEN);
  });

  it('renders Markdown with the spec sections', async () => {
    const report = await scan({ file: critical });
    const md = renderMarkdown(report, 'ja');
    for (const section of [
      '# Aster Guard MCP Security Report',
      '## Summary',
      '## Risk Score',
      '## Findings',
      '## Recommended Fixes',
      '## Safe Configuration Suggestions',
      '## Appendix: Scanned Files',
    ]) {
      expect(md).toContain(section);
    }
    expect(md).not.toContain(RAW_TOKEN);
  });

  it('renders valid JSON with no raw secrets', async () => {
    const report = await scan({ file: critical });
    const json = renderJson(report);
    expect(JSON.parse(json)).toMatchObject({ grade: 'F' });
    expect(json).not.toContain(RAW_TOKEN);
  });

  it('renders a plain summary for MCP consumers', async () => {
    const report = await scan({ file: critical });
    const text = renderPlainSummary(report);
    expect(text).toContain('Risk Score:');
    expect(text).toContain('AG-005');
    expect(text).not.toContain(RAW_TOKEN);
  });

  it('renders SARIF 2.1.0 with one result per finding', async () => {
    const report = await scan({ file: critical });
    const text = renderSarif(report);
    expect(text).not.toContain(RAW_TOKEN);
    const sarif = JSON.parse(text) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string; level: string }>;
      }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results).toHaveLength(report.findings.length);
    expect(sarif.runs[0]?.results.some((r) => r.ruleId === 'AG-005' && r.level === 'error')).toBe(
      true,
    );
    expect(sarif.runs[0]?.tool.driver.rules.some((r) => r.id === 'AG-005')).toBe(true);
  });
});
