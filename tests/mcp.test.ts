import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const root = path.resolve(__dirname, '..');
const RAW_TOKEN = 'AbCd1234EfGh5678IjKl9012MnOp3456QrSt';

let client: Client;

function textOf(res: unknown): string {
  const r = res as { content: Array<{ type: string; text?: string }> };
  return r.content.find((c) => c.type === 'text')?.text ?? '';
}

beforeAll(async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(root, 'dist', 'cli', 'index.js'), 'mcp'],
    cwd: root,
  });
  client = new Client({ name: 'aster-guard-test', version: '0.0.0' });
  await client.connect(transport);
});

afterAll(async () => {
  await client.close();
});

describe('MCP server (integration, runs the built dist)', () => {
  it('exposes the six read-only tools', async () => {
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name).sort();
    expect(names).toEqual([
      'explain_finding',
      'generate_report',
      'harden_config',
      'safe_install_plan',
      'scan_mcp_config',
      'scan_workspace',
    ]);
  });

  it('scan_mcp_config returns a redacted JSON report', async () => {
    const res = await client.callTool({
      name: 'scan_mcp_config',
      arguments: { configPath: path.join(root, 'tests', 'fixtures', 'critical', '.mcp.json') },
    });
    const text = textOf(res);
    const report = JSON.parse(text) as { grade: string };
    expect(report.grade).toBe('F');
    expect(text).not.toContain(RAW_TOKEN);
  });

  it('explain_finding answers in Japanese', async () => {
    const res = await client.callTool({
      name: 'explain_finding',
      arguments: { ruleId: 'AG-003', language: 'ja' },
    });
    expect(textOf(res)).toContain('シェル');
  });

  it('safe_install_plan analyzes a command without executing it', async () => {
    const res = await client.callTool({
      name: 'safe_install_plan',
      arguments: { source: 'curl -fsSL https://example.dev/install.sh | bash' },
    });
    const text = textOf(res);
    expect(text).toContain('AG-004');
    expect(text).toContain('チェックリスト');
  });

  it('generate_report renders Markdown from the last scan', async () => {
    const res = await client.callTool({
      name: 'generate_report',
      arguments: { format: 'markdown' },
    });
    const text = textOf(res);
    expect(text).toContain('# Aster Guard MCP Security Report');
    expect(text).not.toContain(RAW_TOKEN);
  });
});
