import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PATTERNS: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  { re: /curl[^|;&\n]*\|\s*(?:sudo\s+)?(?:[\w./-]*\/)?(?:ba|z|da)?sh\b/i, confidence: 'high' },
  { re: /wget[^|;&\n]*\|\s*(?:sudo\s+)?(?:[\w./-]*\/)?(?:ba|z|da)?sh\b/i, confidence: 'high' },
  { re: /(?:ba|z)?sh\s+<\(\s*(?:curl|wget)/i, confidence: 'high' },
  { re: /npm\s+(?:install|i)\s+(?:-g|--global)\b/, confidence: 'medium' },
  { re: /pip3?\s+install\s+(?:git\+|--index-url|--extra-index-url)/i, confidence: 'medium' },
];

export const AG004: Rule = {
  id: 'AG-004',
  nameEn: 'Dangerous Install Pattern',
  nameJa: '危険なインストールパターン',
  severity: 'high',
  explanationEn:
    'The configuration pipes a remote script into a shell (e.g. "curl … | bash") or installs packages in a risky way. Whatever the remote server sends at that moment runs on your machine unreviewed.',
  explanationJa:
    'リモートのスクリプトをそのままシェルに流し込む（例：「curl … | bash」）など、危険な方法でインストールを行っています。その瞬間にサーバーが返した内容が、確認されないままあなたのマシンで実行されます。',
  recommendationEn:
    'Download the script first, read it, then run it. Prefer pinned package versions (e.g. "npx package@1.2.3") over piped installers.',
  recommendationJa:
    'スクリプトは一度ダウンロードして内容を確認してから実行してください。パイプ実行ではなく、バージョンを固定したパッケージ（例：「npx package@1.2.3」）の利用が安全です。',
  check(target) {
    const findings = [];
    for (const unit of scanUnits(target)) {
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG004, {
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
