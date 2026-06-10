import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { scan } from '../../core/scanner.js';
import { renderJson, renderMarkdown } from '../../core/report.js';
import { detectLocale } from '../../i18n/index.js';
import type { McpState } from '../server.js';

export function registerGenerateReport(server: McpServer, state: McpState): void {
  server.registerTool(
    'generate_report',
    {
      title: 'Generate a report from the latest scan',
      description:
        'Render the most recent scan as a Markdown or JSON report. If no scan has run yet in this ' +
        'session, the current workspace is scanned first (read-only).',
      inputSchema: {
        format: z.enum(['markdown', 'json']).default('markdown'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ format }) => {
      if (!state.lastReport) {
        state.lastReport = await scan({ cwd: process.cwd(), includeHome: false });
      }
      const text =
        format === 'json'
          ? renderJson(state.lastReport)
          : renderMarkdown(state.lastReport, detectLocale());
      return { content: [{ type: 'text', text }] };
    },
  );
}
