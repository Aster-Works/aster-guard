import fs from 'node:fs';
import path from 'node:path';
import type { Finding, Severity } from '../types/finding.js';
import { severityRank } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';
import type { ScanReport } from '../types/report.js';
import { baselineFindings } from './baseline.js';
import { loadPolicy, policyFilePath } from './policy.js';
import { allRules, normalizeRuleId } from '../rules/index.js';
import { discoverFiles, kindForPath, type DiscoveredFile } from './discovery.js';
import { loadTarget } from './parser.js';
import { runRules, sortFindings } from './rule-engine.js';
import { buildReport } from './report.js';

export interface ScanOptions {
  /** Directory to scan; defaults to the current working directory. */
  cwd?: string;
  /** Scan only this file instead of discovering files. */
  file?: string;
  /** Also scan ~/.claude.json and ~/.claude/settings.json. Default true. */
  includeHome?: boolean;
  /** Compare against .aster-guard/baseline.json and report AG-012 changes. */
  compareBaseline?: boolean;
}

export async function loadTargets(
  options: ScanOptions = {},
): Promise<{ scanRoot: string; targets: ScanTarget[] }> {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  let discovered: DiscoveredFile[];
  let scanRoot = cwd;
  if (options.file) {
    const abs = path.resolve(cwd, options.file);
    if (!fs.existsSync(abs)) {
      throw new Error(`File not found: ${abs}`);
    }
    scanRoot = abs;
    if (fs.statSync(abs).isDirectory()) {
      discovered = await discoverFiles(abs, options.includeHome ?? true);
    } else {
      discovered = [{ path: abs, kind: kindForPath(abs) }];
    }
  } else {
    discovered = await discoverFiles(cwd, options.includeHome ?? true);
  }
  const targets = await Promise.all(discovered.map(loadTarget));
  return { scanRoot, targets };
}

function parseErrorFinding(target: ScanTarget): Finding {
  return {
    ruleId: 'AG-000',
    title: 'Unparseable configuration file',
    severity: 'low',
    confidence: 'high',
    file: target.file,
    evidence: target.parseError,
    redactedEvidence: target.parseError,
    explanationEn: `This file could not be parsed, so it was not fully scanned: ${target.parseError}`,
    explanationJa: `このファイルは解析できなかったため、完全にはスキャンされていません: ${target.parseError}`,
    recommendationEn: 'Fix the syntax error and run the scan again.',
    recommendationJa: '構文エラーを修正して、もう一度スキャンしてください。',
  };
}

/**
 * Run a full scan: discover files, parse them, apply every rule, score the
 * result. Never executes any command found in the configurations.
 */
export async function scan(options: ScanOptions = {}): Promise<ScanReport> {
  const { scanRoot, targets } = await loadTargets(options);
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const { policy, error: policyError } = await loadPolicy(cwd);

  const findings = runRules(targets, allRules, { policy });
  for (const t of targets) {
    if (t.parseError) findings.push(parseErrorFinding(t));
  }
  if (options.compareBaseline) {
    findings.push(...(await baselineFindings(cwd, targets)));
  }

  let all = findings;
  if (policy.ignoreRules && policy.ignoreRules.length > 0) {
    const ignored = new Set(policy.ignoreRules.map(normalizeRuleId));
    all = all.filter((f) => !ignored.has(normalizeRuleId(f.ruleId)));
  }
  if (policyError) {
    all.push(policyErrorFinding(cwd, policyError));
  }
  return buildReport(
    scanRoot,
    targets.map((t) => t.file),
    sortFindings(all),
  );
}

function policyErrorFinding(cwd: string, message: string): Finding {
  return {
    ruleId: 'AG-000',
    title: 'Invalid policy file',
    severity: 'low',
    confidence: 'high',
    file: policyFilePath(cwd),
    evidence: message,
    redactedEvidence: message,
    explanationEn: `The team policy file could not be applied: ${message}`,
    explanationJa: `ポリシーファイルを適用できなかったため、無視されました: ${message}`,
    recommendationEn: 'Fix the policy file ("aster-guard policy init" shows the expected shape).',
    recommendationJa:
      'ポリシーファイルを修正してください（雛形は「aster-guard policy init」で確認できます）。',
  };
}

/**
 * Exit-code policy: findings at or above the threshold mean "do not connect
 * yet". Default threshold is `high` (i.e. high or critical findings block).
 */
export function hasBlockingFindings(report: ScanReport, threshold: Severity = 'high'): boolean {
  const rank = severityRank(threshold);
  return report.findings.some((f) => severityRank(f.severity) <= rank);
}
