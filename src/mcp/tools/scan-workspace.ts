import path from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { scan } from '../../core/scanner.js';
import { renderJson, renderPlainSummary } from '../../core/report.js';
import type { McpState } from '../server.js';

export function registerScanWorkspace(server: McpServer, state: McpState): void {
  server.registerTool(
    'scan_workspace',
    {
      title: 'Scan workspace for MCP security issues',
      description:
        'Scan the workspace (.mcp.json, .claude settings, .env files) for MCP security issues. ' +
        'Read-only: nothing is executed or modified. Returns a risk score, grade, and findings with secrets redacted.',
      inputSchema: {
        path: z.string().default('.').describe('Directory to scan'),
        includeHomeConfig: z
          .boolean()
          .default(false)
          .describe('Also scan ~/.claude.json and ~/.claude/settings.json'),
        format: z.enum(['summary', 'json']).default('summary'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ path: dir, includeHomeConfig, format }) => {
      const report = await scan({ cwd: path.resolve(dir), includeHome: includeHomeConfig });
      state.lastReport = report;
      const text = format === 'json' ? renderJson(report) : renderPlainSummary(report);
      return { content: [{ type: 'text', text }] };
    },
  );
}
