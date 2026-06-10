import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PHRASES: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  {
    re: /ignore\s+(?:all\s+|any\s+)?(?:previous\s+|prior\s+|above\s+)?instructions/i,
    confidence: 'high',
  },
  { re: /do\s+not\s+(?:tell|inform|notify|alert)\s+the\s+user/i, confidence: 'high' },
  { re: /without\s+(?:mentioning|telling|informing|notifying)/i, confidence: 'high' },
  { re: /hidden\s+instruction/i, confidence: 'high' },
  { re: /\bsecretly\b/i, confidence: 'medium' },
  { re: /\bsilently\b/i, confidence: 'medium' },
  { re: /system\s+prompt/i, confidence: 'medium' },
  { re: /developer\s+message/i, confidence: 'medium' },
  { re: /before\s+using\s+this\s+tool/i, confidence: 'medium' },
];

export const AG001: Rule = {
  id: 'AG-001',
  nameEn: 'Hidden Agent Instructions in Tool Description',
  nameJa: 'ツール説明文に隠されたAIエージェント向け指示',
  severity: 'high',
  explanationEn:
    'A tool description or server config contains phrases that look like hidden instructions aimed at the AI agent (e.g. "do not tell the user"). This is a known pattern of Tool Poisoning / prompt injection attacks.',
  explanationJa:
    'このMCPの設定やツール説明文に、AIエージェントに対する隠れた指示（例：「ユーザーに知らせずに実行せよ」）と思われる文が含まれています。Tool Poisoning Attack（ツール説明文を悪用したプロンプトインジェクション）の典型的なパターンです。',
  recommendationEn:
    'Do not connect this MCP server until you have verified its source. Read the full tool description and confirm with the vendor why these phrases are present.',
  recommendationJa:
    '提供元を確認できるまで、このMCPサーバーは接続しないでください。説明文の全文を読み、なぜこのような文言が含まれているのか開発元に確認することをおすすめします。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];
    for (const unit of scanUnits(target)) {
      const hit = PHRASES.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG001, {
            target,
            confidence: hit.confidence,
            path: unit.path,
            // Pass the raw value: makeFinding redacts first, then truncates.
            // Truncating here could split a token and defeat redaction.
            evidence: unit.value,
          }),
        );
      }
    }
    return findings;
  },
};
