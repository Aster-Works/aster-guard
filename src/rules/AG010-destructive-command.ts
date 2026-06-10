import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PATTERNS: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  { re: /\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*(?:rf|fr)[a-zA-Z]*\b/, confidence: 'high' },
  { re: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+-[a-zA-Z]*f\b/, confidence: 'high' },
  { re: /\bdel\s+\/s\b/i, confidence: 'high' },
  { re: /\bformat\s+[a-z]:/i, confidence: 'high' },
  { re: /\bmkfs(?:\.[a-z0-9]+)?\b/i, confidence: 'high' },
  { re: /\bchmod\s+-R\s+777\b/, confidence: 'high' },
  { re: /\bchown\s+-R\b/, confidence: 'medium' },
  { re: /\bsudo\b/, confidence: 'medium' },
];

export const AG010: Rule = {
  id: 'AG-010',
  nameEn: 'Dangerous Destructive Command',
  nameJa: '破壊的なコマンド',
  severity: 'critical',
  explanationEn:
    'The configuration contains a destructive command pattern such as "rm -rf", "mkfs", or "sudo". If this runs — intentionally or by injection — it can delete data or take over the system.',
  explanationJa:
    '「rm -rf」「mkfs」「sudo」のような破壊的なコマンドパターンが含まれています。意図的であれインジェクションであれ、これが実行されるとデータの削除やシステムの乗っ取りにつながります。',
  recommendationEn:
    'Remove the destructive command, or isolate it so it can never touch paths you care about. MCP server configs should not need sudo or recursive deletion.',
  recommendationJa:
    '破壊的なコマンドを取り除くか、重要なパスに絶対に触れない形に隔離してください。通常、MCPサーバーの設定にsudoや再帰的削除が必要になることはありません。',
  check(target) {
    const findings = [];
    for (const unit of scanUnits(target)) {
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG010, {
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
