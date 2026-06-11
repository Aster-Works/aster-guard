import type { Finding } from '../types/finding.js';
import { severityRank } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';
import { allRules } from '../rules/index.js';
import type { Rule, RuleContext } from '../rules/rule.js';

/** Sort findings by severity (critical first), then rule id. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) || a.ruleId.localeCompare(b.ruleId),
  );
}

/** Run every rule against every target, dedupe, and sort by severity. */
export function runRules(
  targets: ScanTarget[],
  rules: readonly Rule[] = allRules,
  context?: RuleContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const target of targets) {
    for (const rule of rules) {
      findings.push(...rule.check(target, context));
    }
  }
  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const key = `${f.ruleId}|${f.file ?? ''}|${f.path ?? ''}|${f.redactedEvidence ?? ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return sortFindings(unique);
}
