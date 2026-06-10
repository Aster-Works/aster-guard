import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PATTERNS: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  { re: /base64\s+(?:-d|-D|--decode)\b/, confidence: 'high' },
  { re: /\bfromCharCode\b/, confidence: 'high' },
  { re: /\beval\b/, confidence: 'medium' },
  { re: /\bFunction\s*\(/, confidence: 'medium' },
  { re: /\batob\s*\(/, confidence: 'medium' },
  { re: /\bpython3?\s+-c\b/, confidence: 'medium' },
  { re: /\bnode\s+(?:-e|--eval)\b/, confidence: 'medium' },
  { re: /\bperl\s+-e\b/, confidence: 'medium' },
  { re: /\bruby\s+-e\b/, confidence: 'medium' },
];

export const AG009: Rule = {
  id: 'AG-009',
  nameEn: 'Suspicious Obfuscation',
  nameJa: '不審な難読化・エンコードされたコード',
  severity: 'high',
  explanationEn:
    'The configuration contains encoded or inline-evaluated code (e.g. "base64 -d", "eval", "node -e"). Obfuscation is a common way to hide what a command really does.',
  explanationJa:
    'エンコードされたコードやインライン実行（例：「base64 -d」「eval」「node -e」）が含まれています。難読化は、コマンドの本当の動作を隠すためによく使われる手口です。',
  recommendationEn:
    'Decode and read what is actually being executed before connecting. If the author cannot explain why obfuscation is needed, do not use this server.',
  recommendationJa:
    '接続する前に、実際に何が実行されるのかデコードして確認してください。難読化の理由を開発元が説明できないなら、このサーバーは使わないでください。',
  check(target) {
    const findings = [];
    for (const unit of scanUnits(target)) {
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG009, {
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
