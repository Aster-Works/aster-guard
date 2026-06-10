import fs from 'node:fs';
import path from 'node:path';
import type { Finding } from '../types/finding.js';
import { isBlocking } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';
import type { ScanReport } from '../types/report.js';
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
}

export async function loadTargets(
  options: ScanOptions = {},
): Promise<{ scanRoot: string; targets: ScanTarget[] }> {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  let discovered: DiscoveredFile[];
  if (options.file) {
    const abs = path.resolve(cwd, options.file);
    if (!fs.existsSync(abs)) {
      throw new Error(`File not found: ${abs}`);
    }
    discovered = [{ path: abs, kind: kindForPath(abs) }];
  } else {
    discovered = await discoverFiles(cwd, options.includeHome ?? true);
  }
  const targets = await Promise.all(discovered.map(loadTarget));
  return { scanRoot: options.file ? path.resolve(cwd, options.file) : cwd, targets };
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
  const findings = runRules(targets);
  for (const t of targets) {
    if (t.parseError) findings.push(parseErrorFinding(t));
  }
  return buildReport(
    scanRoot,
    targets.map((t) => t.file),
    sortFindings(findings),
  );
}

/** Exit-code policy: high or critical findings mean "do not connect yet". */
export function hasBlockingFindings(report: ScanReport): boolean {
  return report.findings.some((f) => isBlocking(f.severity));
}
