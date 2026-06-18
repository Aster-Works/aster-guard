import type { Messages } from './en.js';

export const ja: Messages = {
  reportTitle: 'Aster Guard MCP セキュリティレポート',
  target: '対象',
  scannedFiles: 'スキャンしたファイル',
  noScannedFiles: '対応する設定ファイルが見つかりませんでした。',
  riskScore: 'リスクスコア',
  grade: '評価',
  findingsLabel: '検出された問題',
  noFindings: 'セキュリティ上の問題は見つかりませんでした。この設定は安全に使えそうです。',
  file: 'ファイル',
  evidence: '該当箇所',
  recommendation: '対策',
  nextStepsTitle: '次のアクション',
  nextStepStar: 'Starで応援',
  nextStepIssue: '不具合・要望を報告',
  nextStepShare: 'Xで共有',
  nextStepFeedback: '任意フィードバックを送る',
  severityName: {
    critical: '重大',
    high: '高',
    medium: '中',
    low: '低',
    info: '情報',
  },
  summaryCounts: (counts) => {
    const names = { critical: '重大', high: '高', medium: '中', low: '低', info: '情報' } as const;
    const parts: string[] = [];
    for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      if (counts[sev] > 0) parts.push(`${names[sev]} ${counts[sev]}件`);
    }
    return parts.length > 0 ? parts.join('、') : '問題なし';
  },
  summaryClean: 'セキュリティ上の問題は検出されませんでした。',
  parseErrorLabel: 'ファイルを解析できませんでした',
};
