import type { Confidence, Finding, Severity } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits, truncate } from './helpers.js';
import { analyzeStego, stripDeceptive, type StegoCategory } from './unicode-stego.js';
import { HIGH_CONFIDENCE_INJECTION } from './injection-phrases.js';

interface CategoryMeta {
  severity: Severity;
  confidence: Confidence;
  detailEn: string;
  detailJa: string;
}

const CATEGORY_META: Record<StegoCategory, CategoryMeta> = {
  tag: {
    severity: 'critical',
    confidence: 'high',
    detailEn: 'Unicode Tag characters (U+E0000–E007F) — invisible, decode to ASCII; classic ASCII-smuggling payload',
    detailJa: 'Unicodeタグ文字（U+E0000–E007F）。不可視でASCIIにデコードでき、ASCIIスマグリングの典型的なペイロードです',
  },
  bidi: {
    severity: 'high',
    confidence: 'high',
    detailEn: 'bidirectional control characters — can reorder displayed text so it differs from the real bytes (Trojan Source)',
    detailJa: '双方向制御文字。表示順を実際のバイト列と食い違わせられます（Trojan Source攻撃）',
  },
  ansi: {
    severity: 'high',
    confidence: 'high',
    detailEn: 'ANSI/terminal escape or control character — can hide or rewrite text in a terminal',
    detailJa: 'ANSI/ターミナルのエスケープ・制御文字。ターミナル上で文字を隠したり書き換えたりできます',
  },
  invisible: {
    severity: 'medium',
    confidence: 'high',
    detailEn: 'zero-width / invisible formatting characters — often used to split words and slip text past keyword filters',
    detailJa: 'ゼロ幅・不可視の書式文字。単語を分断してキーワード検査をすり抜けさせる手口によく使われます',
  },
  'variation-selector': {
    severity: 'medium',
    confidence: 'medium',
    detailEn: 'variation selectors — the supplementary range can be abused to smuggle hidden data',
    detailJa: '異体字セレクタ。補助範囲は隠しデータの密輸に悪用されることがあります',
  },
  'line-separator': {
    severity: 'medium',
    confidence: 'medium',
    detailEn: 'Unicode line/paragraph separators — can hide content that appears on a separate visual line',
    detailJa: 'Unicodeの行・段落区切り文字。別の表示行に隠れた内容を仕込めます',
  },
  homoglyph: {
    severity: 'medium',
    confidence: 'medium',
    detailEn: 'mixed-script homoglyphs (Latin combined with Cyrillic/Greek in one word) — used to imitate trusted names and evade filters',
    detailJa: '混在スクリプトのホモグリフ（1語の中でLatinとキリル/ギリシャ文字が混在）。信頼された名前への偽装やフィルタ回避に使われます',
  },
};

/** Show the deceptive characters first; tag/bidi/ansi are the most dangerous. */
const CATEGORY_ORDER: StegoCategory[] = [
  'tag',
  'bidi',
  'ansi',
  'invisible',
  'variation-selector',
  'line-separator',
  'homoglyph',
];

export const AG016: Rule = {
  id: 'AG-016',
  nameEn: 'Hidden Unicode / Steganographic Text',
  nameJa: '不可視Unicode・ステガノグラフィの隠しテキスト',
  severity: 'high',
  explanationEn:
    'A configuration string contains deceptive characters that are invisible or misleading when rendered: ' +
    'zero-width spaces, Unicode Tag characters, bidirectional overrides, ANSI escape codes, or mixed-script homoglyphs. ' +
    'These have no legitimate purpose in an MCP config and are a known way to hide prompt-injection instructions from both humans and keyword-based scanners.',
  explanationJa:
    'このMCP設定の文字列に、画面表示では見えない・誤認させる文字が含まれています。' +
    'ゼロ幅スペース、Unicodeタグ文字、双方向上書き、ANSIエスケープ、混在スクリプトのホモグリフなどです。' +
    'これらはMCP設定に正当な用途がなく、プロンプトインジェクションの指示を人間にもキーワード検査にも気づかせずに隠すための既知の手口です。',
  recommendationEn:
    'Treat this server as untrusted until explained. Inspect the raw bytes of the flagged string (the report shows hidden characters as ‹U+XXXX› markers) and confirm with the author why non-printing characters are present.',
  recommendationJa:
    '説明がつくまでこのサーバーは信頼しないでください。指摘された文字列の生バイトを確認し（レポートでは隠し文字を ‹U+XXXX› で可視化しています）、なぜ非表示文字が含まれるのか開発元に確認してください。',
  check(target) {
    const findings: Finding[] = [];

    for (const unit of scanUnits(target)) {
      const analysis = analyzeStego(unit.value);
      if (!analysis.hasAny) continue;

      // Two-stage escalation: if removing the deceptive characters reveals an
      // injection imperative that was NOT matchable in the raw string, this is
      // active steganographic prompt injection — escalate to critical.
      const stripped = stripDeceptive(unit.value);
      const revealed =
        HIGH_CONFIDENCE_INJECTION.some((re) => re.test(stripped)) &&
        !HIGH_CONFIDENCE_INJECTION.some((re) => re.test(unit.value));

      const visualized = truncate(analysis.visualized);

      if (revealed) {
        findings.push(
          makeFinding(AG016, {
            target,
            severity: 'critical',
            confidence: 'high',
            path: unit.path,
            evidence: visualized,
            detailEn: `removing the hidden characters reveals a prompt-injection instruction: "${truncate(stripped, 80)}"`,
            detailJa: `隠し文字を取り除くとプロンプトインジェクションの指示が現れます：「${truncate(stripped, 80)}」`,
          }),
        );
        // The 'invisible' category is the smuggling mechanism for this finding;
        // don't also emit a separate medium finding for it.
        analysis.categories.delete('invisible');
      }

      for (const category of CATEGORY_ORDER) {
        if (!analysis.categories.has(category)) continue;
        const meta = CATEGORY_META[category];
        findings.push(
          makeFinding(AG016, {
            target,
            severity: meta.severity,
            confidence: meta.confidence,
            path: unit.path,
            evidence: visualized,
            detailEn: meta.detailEn,
            detailJa: meta.detailJa,
          }),
        );
      }
    }

    return findings;
  },
};
