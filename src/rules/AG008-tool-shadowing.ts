import type { Rule } from './rule.js';
import { commandLine, makeFinding } from './helpers.js';

const TRUSTED_NAMES = [
  'github',
  'filesystem',
  'terminal',
  'bash',
  'read_file',
  'write_file',
  'search',
];

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[-_\s]/g, '');
}

export const AG008: Rule = {
  id: 'AG-008',
  nameEn: 'Tool Name Shadowing',
  nameJa: '既知ツール名のなりすまし（シャドーイング）',
  severity: 'medium',
  explanationEn:
    'A server uses the same name as a well-known trusted tool (e.g. "github", "filesystem") but does not appear to be the official implementation. Attackers use familiar names to make malicious servers look safe.',
  explanationJa:
    'よく知られた信頼済みツールと同じ名前（例：「github」「filesystem」）のサーバーですが、公式の実装ではない可能性があります。攻撃者は見慣れた名前を使って、悪意あるサーバーを安全に見せかけることがあります。',
  recommendationEn:
    'Check the command or package behind this entry. If it is not the implementation you expect, rename or remove it.',
  recommendationJa:
    'このエントリが実際に起動するコマンドやパッケージを確認してください。期待した実装と違う場合は、名前を変えるか削除しましょう。',
  check(target) {
    const findings = [];
    for (const server of target.servers) {
      const n = normalizeName(server.name);
      const match = TRUSTED_NAMES.find((t) => normalizeName(t) === n);
      if (!match) continue;
      const cl = commandLine(server).toLowerCase();
      if (cl.includes(`@modelcontextprotocol/server-${match}`)) continue; // official package
      findings.push(
        makeFinding(AG008, {
          target,
          confidence: 'low',
          path: server.jsonPath,
          evidence: cl || server.url || server.name,
          detailEn: `server name "${server.name}"`,
          detailJa: `サーバー名「${server.name}」`,
        }),
      );
    }
    return findings;
  },
};
