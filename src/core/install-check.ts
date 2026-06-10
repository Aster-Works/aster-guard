import type { ScanTarget } from '../types/config.js';
import type { Finding } from '../types/finding.js';
import { extractServers } from './parser.js';
import { runRules } from './rule-engine.js';

export const INSTALL_CHECKLIST = `Safety checklist before installing an MCP server / MCPサーバー導入前チェックリスト:
1. Verify the author/organization behind the package or repository. / パッケージ・リポジトリの提供元（作者・組織）を確認する。
2. Check repository activity: stars, recent commits, open issues. / スター数・更新履歴・Issueの状況を確認する。
3. Pin an exact version (e.g. package@1.2.3) instead of "latest". / バージョンを固定してインストールする（latestを避ける）。
4. Grant the narrowest possible permissions and paths first. / 最初は最小限の権限・最小限のパスで試す。
5. Re-run "aster-guard scan" after adding it to your config. / 設定に追加したら aster-guard scan を再実行する。`;

/**
 * Statically analyze an install command / package name / repo URL by wrapping
 * it in a synthetic config and running the normal rule set on it. Nothing is
 * executed or fetched.
 */
export function analyzeInstallSource(source: string): Finding[] {
  const json = { mcpServers: { 'install-candidate': { command: source } } };
  const target: ScanTarget = {
    file: '<install-candidate>',
    kind: 'mcp-config',
    raw: source,
    json,
    servers: extractServers(json, '<install-candidate>'),
    envVars: [],
  };
  return runRules([target]);
}
