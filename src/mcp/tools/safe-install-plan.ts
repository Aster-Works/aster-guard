import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ScanTarget } from '../../types/config.js';
import { extractServers } from '../../core/parser.js';
import { runRules } from '../../core/rule-engine.js';

const CHECKLIST = `Safety checklist before installing an MCP server / MCPサーバー導入前チェックリスト:
1. Verify the author/organization behind the package or repository. / パッケージ・リポジトリの提供元（作者・組織）を確認する。
2. Check repository activity: stars, recent commits, open issues. / スター数・更新履歴・Issueの状況を確認する。
3. Pin an exact version (e.g. package@1.2.3) instead of "latest". / バージョンを固定してインストールする（latestを避ける）。
4. Grant the narrowest possible permissions and paths first. / 最初は最小限の権限・最小限のパスで試す。
5. Re-run "aster-guard scan" after adding it to your config. / 設定に追加したら aster-guard scan を再実行する。`;

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
      // Wrap the string in a synthetic config so the normal rule set can run on it.
      const json = { mcpServers: { 'install-candidate': { command: source } } };
      const target: ScanTarget = {
        file: '<install-candidate>',
        kind: 'mcp-config',
        raw: source,
        json,
        servers: extractServers(json, '<install-candidate>'),
        envVars: [],
      };
      const findings = runRules([target]);
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
      lines.push(CHECKLIST);
      if (allowNetwork) {
        lines.push('');
        lines.push('Note: allowNetwork is ignored in v0.1; no remote code was fetched.');
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );
}
