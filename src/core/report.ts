import pc from 'picocolors';
import type { Finding, Severity } from '../types/finding.js';
import { SEVERITY_ORDER } from '../types/finding.js';
import type { Grade, ScanReport } from '../types/report.js';
import { getMessages, type Locale } from '../i18n/index.js';
import { getRule } from '../rules/index.js';
import { computeRiskScore, gradeForScore } from './scoring.js';
import { VERSION } from '../version.js';

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function buildReport(
  target: string,
  scannedFiles: string[],
  findings: Finding[],
): ScanReport {
  const riskScore = computeRiskScore(findings);
  const counts = countBySeverity(findings);
  const ja = getMessages('ja');
  const en = getMessages('en');
  return {
    target,
    scannedFiles,
    riskScore,
    grade: gradeForScore(riskScore),
    findings,
    summaryJa:
      findings.length === 0 ? ja.summaryClean : `検出された問題: ${ja.summaryCounts(counts)}`,
    summaryEn: findings.length === 0 ? en.summaryClean : `Findings: ${en.summaryCounts(counts)}`,
  };
}

function gradeColored(grade: Grade): string {
  switch (grade) {
    case 'A':
      return pc.green(pc.bold(grade));
    case 'B':
      return pc.green(grade);
    case 'C':
      return pc.yellow(pc.bold(grade));
    case 'D':
      return pc.red(grade);
    case 'F':
      return pc.red(pc.bold(grade));
  }
}

function severityColored(severity: Severity, label: string): string {
  const badge = `[${label}]`;
  switch (severity) {
    case 'critical':
      return pc.bgRed(pc.white(badge));
    case 'high':
      return pc.red(badge);
    case 'medium':
      return pc.yellow(badge);
    case 'low':
      return pc.cyan(badge);
    case 'info':
      return pc.dim(badge);
  }
}

function findingDisplayName(f: Finding, locale: Locale): string {
  const rule = getRule(f.ruleId);
  return locale === 'ja' && rule ? rule.nameJa : f.title;
}

const otherLocale = (locale: Locale): Locale => (locale === 'ja' ? 'en' : 'ja');

const PROJECT_URL = 'https://github.com/Aster-Works/aster-guard';
const ISSUE_URL = `${PROJECT_URL}/issues/new`;
const FEEDBACK_URL = `${PROJECT_URL}/issues/new?template=feedback.yml`;
const X_SHARE_URL =
  'https://twitter.com/intent/tweet?' +
  new URLSearchParams({
    text: 'I checked my MCP config with Aster Guard before connecting it.',
    url: PROJECT_URL,
  }).toString();

const SUPPORT_LINKS = [
  { key: 'nextStepStar', url: PROJECT_URL },
  { key: 'nextStepIssue', url: ISSUE_URL },
  { key: 'nextStepShare', url: X_SHARE_URL },
  { key: 'nextStepFeedback', url: FEEDBACK_URL },
] as const;

function appendTerminalNextSteps(lines: string[], locale: Locale): void {
  const m = getMessages(locale);
  lines.push('');
  lines.push(pc.bold(`${m.nextStepsTitle}:`));
  for (const link of SUPPORT_LINKS) {
    lines.push(`  - ${m[link.key]}: ${link.url}`);
  }
}

function explanationFor(f: Finding, locale: Locale): string {
  return locale === 'ja' ? f.explanationJa : f.explanationEn;
}

function recommendationFor(f: Finding, locale: Locale): string {
  return locale === 'ja' ? f.recommendationJa : f.recommendationEn;
}

/** Human-friendly terminal report (Japanese when the system locale is ja). */
export function renderTerminal(report: ScanReport, locale: Locale): string {
  const m = getMessages(locale);
  const second = otherLocale(locale);
  const mSecond = getMessages(second);
  const lines: string[] = [];
  lines.push(pc.bold(m.reportTitle));
  lines.push('');
  lines.push(`${m.target}: ${report.target}`);
  if (report.scannedFiles.length > 0) {
    lines.push(`${m.scannedFiles}:`);
    for (const f of report.scannedFiles) lines.push(`  - ${f}`);
  } else {
    lines.push(m.noScannedFiles);
  }
  lines.push('');
  lines.push(
    `${m.riskScore}: ${pc.bold(String(report.riskScore))} / 100    ${m.grade}: ${gradeColored(report.grade)}`,
  );
  lines.push(locale === 'ja' ? report.summaryJa : report.summaryEn);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push(pc.green(m.noFindings));
    appendTerminalNextSteps(lines, locale);
    return lines.join('\n') + '\n';
  }

  for (const sev of SEVERITY_ORDER) {
    for (const f of report.findings.filter((x) => x.severity === sev)) {
      lines.push(
        `${severityColored(sev, m.severityName[sev])} ${pc.bold(`${f.ruleId} ${findingDisplayName(f, locale)}`)}`,
      );
      if (f.file) lines.push(`  ${m.file}: ${f.file}${f.path ? `  (${f.path})` : ''}`);
      if (f.redactedEvidence) lines.push(`  ${m.evidence}: ${f.redactedEvidence}`);
      lines.push(`  ${explanationFor(f, locale)}`);
      lines.push(pc.dim(`  ${explanationFor(f, second)}`));
      lines.push(`  ${m.recommendation}: ${recommendationFor(f, locale)}`);
      lines.push(pc.dim(`  ${mSecond.recommendation}: ${recommendationFor(f, second)}`));
      lines.push('');
    }
  }
  appendTerminalNextSteps(lines, locale);
  return lines.join('\n').trimEnd() + '\n';
}

export function renderJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/** SARIF 2.1.0 output for CI integrations (GitHub code scanning etc.). */
export function renderSarif(report: ScanReport): string {
  const levelFor = (s: Severity): 'error' | 'warning' | 'note' =>
    s === 'critical' || s === 'high' ? 'error' : s === 'medium' ? 'warning' : 'note';
  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))].sort();
  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aster Guard MCP',
            informationUri: 'https://www.npmjs.com/package/@asterworks/aster-guard',
            version: VERSION,
            rules: ruleIds.map((id) => {
              const rule = getRule(id);
              return {
                id,
                shortDescription: { text: rule?.nameEn ?? id },
                fullDescription: { text: rule?.explanationEn ?? '' },
              };
            }),
          },
        },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          level: levelFor(f.severity),
          message: {
            text: f.explanationEn + (f.redactedEvidence ? ` Evidence: ${f.redactedEvidence}` : ''),
          },
          locations: f.file
            ? [{ physicalLocation: { artifactLocation: { uri: 'file://' + encodeURI(f.file) } } }]
            : [],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

/** Compact, color-free summary used by the MCP tools. */
export function renderPlainSummary(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`Risk Score: ${report.riskScore} / 100 (Grade ${report.grade})`);
  lines.push(report.summaryEn);
  lines.push(report.summaryJa);
  if (report.scannedFiles.length > 0) {
    lines.push(`Scanned: ${report.scannedFiles.join(', ')}`);
  } else {
    lines.push('Scanned: (no supported configuration files found)');
  }
  for (const f of report.findings) {
    lines.push('');
    lines.push(`- [${f.severity}/${f.confidence}] ${f.ruleId} ${f.title}`);
    if (f.file) lines.push(`  file: ${f.file}${f.path ? ` (${f.path})` : ''}`);
    if (f.redactedEvidence) lines.push(`  evidence: ${f.redactedEvidence}`);
    lines.push(`  ja: ${f.explanationJa}`);
    lines.push(`  fix: ${f.recommendationJa}`);
  }
  return lines.join('\n');
}

const SAFE_SUGGESTIONS: ReadonlyArray<{ en: string; ja: string }> = [
  {
    en: 'Move hardcoded secrets to environment variables and reference them as `${VAR_NAME}`.',
    ja: 'ハードコードされた秘密情報は環境変数へ移し、`${VAR_NAME}` 形式で参照する。',
  },
  {
    en: 'Avoid `curl | bash`-style installs; download, review, then run pinned versions.',
    ja: '`curl | bash` 形式のインストールを避け、ダウンロードして内容確認のうえバージョン固定で実行する。',
  },
  {
    en: 'Narrow filesystem access to the specific project directories a server needs.',
    ja: 'ファイルシステムへのアクセスは、サーバーが実際に必要とするプロジェクトディレクトリに限定する。',
  },
  {
    en: 'Add Claude Code permission deny rules for `.env` and other secret files.',
    ja: 'Claude Codeのpermissions設定に、`.env` などの秘密ファイルへのdenyルールを追加する。',
  },
  {
    en: 'Prefer explicit command arguments over shell strings like `bash -c "..."`.',
    ja: '`bash -c "..."` のようなシェル文字列ではなく、明示的なコマンド引数で起動する。',
  },
];

/** Markdown report with the sections defined in the spec. */
export function renderMarkdown(report: ScanReport, locale: Locale): string {
  const m = getMessages(locale);
  const second = otherLocale(locale);
  const mSecond = getMessages(second);
  const counts = countBySeverity(report.findings);
  const md: string[] = [];
  md.push('# Aster Guard MCP Security Report');
  md.push('');
  md.push('## Summary');
  md.push('');
  md.push(`- ${m.target}: \`${report.target}\``);
  md.push(`- ${locale === 'ja' ? report.summaryJa : report.summaryEn}`);
  md.push('');
  md.push('## Risk Score');
  md.push('');
  md.push(`**${report.riskScore} / 100** — ${m.grade} **${report.grade}**`);
  md.push('');
  md.push('## Findings');
  md.push('');
  if (report.findings.length === 0) {
    md.push(m.noFindings);
    md.push('');
  } else {
    for (const sev of SEVERITY_ORDER) {
      const group = report.findings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      md.push(`### ${m.severityName[sev]} (${counts[sev]})`);
      md.push('');
      for (const f of group) {
        md.push(`#### ${f.ruleId} ${findingDisplayName(f, locale)}`);
        md.push('');
        if (f.file) md.push(`- ${m.file}: \`${f.file}\`${f.path ? ` (\`${f.path}\`)` : ''}`);
        if (f.redactedEvidence) md.push(`- ${m.evidence}: \`${f.redactedEvidence}\``);
        md.push('');
        md.push(explanationFor(f, locale));
        md.push('');
        md.push(`_${explanationFor(f, second)}_`);
        md.push('');
        md.push(`**${m.recommendation}:** ${recommendationFor(f, locale)}`);
        md.push('');
        md.push(`**${mSecond.recommendation}:** ${recommendationFor(f, second)}`);
        md.push('');
      }
    }
  }
  md.push('## Recommended Fixes');
  md.push('');
  const seenRules = new Set<string>();
  for (const f of report.findings) {
    if (seenRules.has(f.ruleId)) continue;
    seenRules.add(f.ruleId);
    md.push(`- **${f.ruleId}**: ${locale === 'ja' ? f.recommendationJa : f.recommendationEn}`);
  }
  if (seenRules.size === 0)
    md.push(locale === 'ja' ? '- 修正が必要な項目はありません。' : '- Nothing to fix.');
  md.push('');
  md.push('## Safe Configuration Suggestions');
  md.push('');
  for (const s of SAFE_SUGGESTIONS) md.push(`- ${locale === 'ja' ? s.ja : s.en}`);
  md.push('');
  md.push('## Appendix: Scanned Files');
  md.push('');
  if (report.scannedFiles.length === 0) {
    md.push(m.noScannedFiles);
  } else {
    for (const f of report.scannedFiles) md.push(`- \`${f}\``);
  }
  md.push('');
  md.push('## Next Steps');
  md.push('');
  for (const link of SUPPORT_LINKS) {
    md.push(`- **${m[link.key]}**: ${link.url}`);
  }
  md.push('');
  return md.join('\n');
}
