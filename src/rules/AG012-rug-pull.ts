import type { Rule } from './rule.js';

/**
 * AG-012 findings are produced by the baseline comparison in
 * `src/core/baseline.ts`, not by the normal rule runner — detecting a rug
 * pull requires the stored baseline as context. This entry exists so the
 * rule can be listed and explained like any other.
 */
export const AG012: Rule = {
  id: 'AG-012',
  nameEn: 'MCP Rug Pull Risk',
  nameJa: 'MCPラグプル（承認後の変更）リスク',
  severity: 'high',
  explanationEn:
    'A previously approved MCP server definition (command, args, URL, or env keys) changed after the baseline was created. Malicious servers sometimes turn hostile after gaining trust — a "rug pull".',
  explanationJa:
    '承認済みMCPサーバーの定義（コマンド・引数・URL・環境変数キー）が、ベースライン作成後に変更されています。信頼を得た後で挙動を変える「ラグプル」攻撃の典型的な兆候です。',
  recommendationEn:
    'Review the change and confirm it came from a source you trust. If it is intentional, refresh the snapshot with "aster-guard baseline create".',
  recommendationJa:
    '変更内容を確認し、信頼できる提供元による意図的な変更かを確かめてください。問題なければ「aster-guard baseline create」でベースラインを更新しましょう。',
  check() {
    return [];
  },
};
