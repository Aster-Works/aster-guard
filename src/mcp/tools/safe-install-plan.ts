import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { analyzeInstallSource, INSTALL_CHECKLIST } from '../../core/install-check.js';

export function registerSafeInstallPlan(server: McpServer): void {
  server.registerTool(
    'safe_install_plan',
    {
      title: 'Evaluate an MCP install command',
      description:
        'Statically analyze a proposed MCP server install command, package name, or repository URL ' +
        'and return detected risks plus a safety checklist. v0.1 never fetches remote code — only ' +
        'the given string is analyzed.',
      inputSchema: {
        source: z.string().describe('Install command, npm package, or repository URL'),
        allowNetwork: z
          .boolean()
          .default(false)
          .describe('Ignored in v0.1: remote fetching is not implemented yet'),
      },
      annotations: { readOnlyHint: true },
    },
    ({ source, allowNetwork }) => {
      const findings = analyzeInstallSource(source);
      const lines: string[] = [];
      if (findings.length === 0) {
        lines.push('No known risky patterns detected in the given string.');
        lines.push('検査した文字列からは、既知の危険なパターンは見つかりませんでした。');
        lines.push('(This is a static check only — it does not prove the package is safe.)');
      } else {
        lines.push(`Detected ${findings.length} risk signal(s):`);
        for (const f of findings) {
          lines.push(`- [${f.severity}] ${f.ruleId} ${f.title}`);
          lines.push(`  ${f.explanationJa}`);
          lines.push(`  fix: ${f.recommendationJa}`);
        }
      }
      lines.push('');
      lines.push(INSTALL_CHECKLIST);
      if (allowNetwork) {
        lines.push('');
        lines.push('Note: allowNetwork is ignored in v0.1; no remote code was fetched.');
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );
}
