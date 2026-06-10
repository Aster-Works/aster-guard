import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { scan } from '../../core/scanner.js';
import { renderJson } from '../../core/report.js';
import type { McpState } from '../server.js';

export function registerScanMcpConfig(server: McpServer, state: McpState): void {
  server.registerTool(
    'scan_mcp_config',
    {
      title: 'Scan a specific MCP config file',
      description:
        'Scan one MCP configuration file (e.g. .mcp.json) for security issues. ' +
        'Read-only; secrets in the result are redacted. Returns the full report as JSON.',
      inputSchema: {
        configPath: z.string().describe('Path to the configuration file to scan'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ configPath }) => {
      try {
        const report = await scan({ file: configPath });
        state.lastReport = report;
        return { content: [{ type: 'text', text: renderJson(report) }] };
      } catch (err) {
        return {
          content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
          isError: true,
        };
      }
    },
  );
}
