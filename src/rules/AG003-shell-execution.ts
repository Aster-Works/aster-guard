import path from 'node:path';
import type { Rule } from './rule.js';
import { commandLine, makeFinding, scanUnits } from './helpers.js';

const SHELLS = new Set([
  'bash',
  'sh',
  'zsh',
  'dash',
  'fish',
  'powershell',
  'pwsh',
  'cmd',
  'cmd.exe',
]);

const PATTERNS: ReadonlyArray<{ re: RegExp; confidence: 'high' | 'medium' }> = [
  { re: /\b(?:bash|zsh|powershell|pwsh|cmd(?:\.exe)?)\s+(?:-c|\/c)\b/i, confidence: 'high' },
  {
    re: /child_process|\bexecSync\b|\bspawnSync?\s*\(|\bsubprocess\b|os\.system/,
    confidence: 'medium',
  },
];

export const AG003: Rule = {
  id: 'AG-003',
  nameEn: 'Shell Command Execution Capability',
  nameJa: 'シェルコマンド実行能力',
  severity: 'high',
  explanationEn:
    'This MCP server runs through a shell (e.g. "bash -c") or advertises the ability to execute shell commands. A shell gives the server — and anything that can influence it — the power to run arbitrary commands on your machine.',
  explanationJa:
    'このMCPサーバーはシェル経由で起動される（例：「bash -c」）か、シェルコマンドを実行する能力を持っています。シェルを使えるサーバーは、あなたのマシン上で任意のコマンドを実行できてしまいます。',
  recommendationEn:
    'Review exactly what the command does. Prefer launching the server binary directly with explicit arguments instead of a shell string, and restrict what it is allowed to do.',
  recommendationJa:
    'コマンドの内容を必ず確認してください。シェル文字列ではなく、サーバーの実行ファイルを明示的な引数で直接起動する形が安全です。許可する操作も最小限に絞りましょう。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];
    const flaggedServers = new Set<string>();

    for (const server of target.servers) {
      if (server.command && SHELLS.has(path.basename(server.command).toLowerCase())) {
        flaggedServers.add(server.jsonPath);
        findings.push(
          makeFinding(AG003, {
            target,
            confidence: 'high',
            path: server.jsonPath,
            evidence: commandLine(server),
          }),
        );
      }
    }

    for (const unit of scanUnits(target)) {
      if (unit.server && flaggedServers.has(unit.server.jsonPath)) continue;
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG003, {
            target,
            confidence: hit.confidence,
            path: unit.path,
            evidence: unit.value,
          }),
        );
      }
    }
    return findings;
  },
};
