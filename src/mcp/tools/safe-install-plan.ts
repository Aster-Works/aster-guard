import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  analyzeInstallSource,
  analyzeRemote,
  INSTALL_CHECKLIST,
  renderRemoteSignals,
} from '../../core/install-check.js';

export function registerSafeInstallPlan(server: McpServer): void {
  server.registerTool(
    'safe_install_plan',
    {
      title: 'Evaluate an MCP install command',
      description:
        'Analyze a proposed MCP server install command, package name, or repository URL and return ' +
        'detected risks plus a safety checklist. Static analysis by default; with allowNetwork=true ' +
        'it also fetches npm/GitHub metadata over HTTPS (JSON only — code is never downloaded or executed).',
      inputSchema: {
        source: z.string().describe('Install command, npm package, or repository URL'),
        allowNetwork: z
          .boolean()
          .default(false)
          .describe('Also check npm/GitHub metadata (existence, install scripts, age, downloads)'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ source, allowNetwork }) => {
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
      if (allowNetwork) {
        const signals = await analyzeRemote(source);
        lines.push('');
        lines.push('Remote check (metadata only) / リモート検査:');
        for (const s of signals) lines.push(`- [${s.level}] ${s.en}`, `  ${s.ja}`);
        if (signals.length === 0) lines.push(...renderRemoteSignals(signals, 'en'));
      }
      lines.push('');
      lines.push(INSTALL_CHECKLIST);
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );
}
