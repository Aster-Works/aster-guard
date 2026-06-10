import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import type { NormalizedServer, ScanTarget } from '../types/config.js';
import type { Confidence, Finding, Severity } from '../types/finding.js';
import { redactText } from './redaction.js';
import { AG012 } from '../rules/AG012-rug-pull.js';

export interface BaselineEntry {
  /** `<sourceFile>::<serverName>` */
  key: string;
  command?: string;
  args: string[];
  url?: string;
  envKeys: string[];
  headerKeys: string[];
  hash: string;
}

export interface BaselineFile {
  version: 1;
  createdAt: string;
  entries: BaselineEntry[];
}

export function baselineFilePath(cwd: string): string {
  return path.join(cwd, '.aster-guard', 'baseline.json');
}

function entryForServer(server: NormalizedServer): BaselineEntry {
  // Stored fields are redacted; env/header VALUES are never written to disk —
  // only the key names, which is enough to detect shape changes.
  const command = server.command === undefined ? undefined : redactText(server.command);
  const args = server.args.map((a) => redactText(a));
  const url = server.url === undefined ? undefined : redactText(server.url);
  const envKeys = Object.keys(server.env).sort();
  const headerKeys = Object.keys(server.headers).sort();
  const hash = crypto
    .createHash('sha256')
    .update(JSON.stringify({ command, args, url, envKeys, headerKeys }))
    .digest('hex');
  return {
    key: `${server.sourceFile}::${server.name}`,
    command,
    args,
    url,
    envKeys,
    headerKeys,
    hash,
  };
}

export async function createBaseline(
  targets: ScanTarget[],
  cwd: string,
): Promise<{ file: string; count: number }> {
  const entries = targets.flatMap((t) => t.servers).map(entryForServer);
  entries.sort((a, b) => a.key.localeCompare(b.key));
  const file = baselineFilePath(cwd);
  await fs.mkdir(path.dirname(file), { recursive: true });
  const data: BaselineFile = {
    version: 1,
    createdAt: new Date().toISOString(),
    entries,
  };
  await fs.writeFile(file, JSON.stringify(data, null, 2) + '\n', 'utf8');
  return { file, count: entries.length };
}

export async function loadBaseline(cwd: string): Promise<BaselineFile | null> {
  try {
    const raw = await fs.readFile(baselineFilePath(cwd), 'utf8');
    const data = JSON.parse(raw) as BaselineFile;
    return Array.isArray(data.entries) ? data : null;
  } catch {
    return null;
  }
}

interface Ag012Options {
  severity: Severity;
  confidence: Confidence;
  file?: string;
  path?: string;
  evidence?: string;
  detailEn: string;
  detailJa: string;
}

function ag012Finding(opts: Ag012Options): Finding {
  return {
    ruleId: AG012.id,
    title: AG012.nameEn,
    severity: opts.severity,
    confidence: opts.confidence,
    file: opts.file,
    path: opts.path,
    evidence: opts.evidence,
    redactedEvidence: opts.evidence,
    explanationEn: `${AG012.explanationEn} ${opts.detailEn}`,
    explanationJa: `${AG012.explanationJa} ${opts.detailJa}`,
    recommendationEn: AG012.recommendationEn,
    recommendationJa: AG012.recommendationJa,
  };
}

export function compareWithBaseline(targets: ScanTarget[], baseline: BaselineFile): Finding[] {
  const findings: Finding[] = [];
  const baseMap = new Map(baseline.entries.map((e) => [e.key, e]));
  const seen = new Set<string>();

  for (const target of targets) {
    for (const server of target.servers) {
      const current = entryForServer(server);
      seen.add(current.key);
      const base = baseMap.get(current.key);
      if (!base) {
        findings.push(
          ag012Finding({
            severity: 'medium',
            confidence: 'high',
            file: server.sourceFile,
            path: server.jsonPath,
            evidence: [current.command, current.url].filter(Boolean).join(' '),
            detailEn: `Server "${server.name}" was added after the baseline was created.`,
            detailJa: `サーバー「${server.name}」はベースライン作成後に追加されたものです。`,
          }),
        );
        continue;
      }
      if (base.hash !== current.hash) {
        const changed: string[] = [];
        if (base.command !== current.command) changed.push('command');
        if (JSON.stringify(base.args) !== JSON.stringify(current.args)) changed.push('args');
        if (base.url !== current.url) changed.push('url');
        if (JSON.stringify(base.envKeys) !== JSON.stringify(current.envKeys))
          changed.push('env keys');
        if (JSON.stringify(base.headerKeys) !== JSON.stringify(current.headerKeys))
          changed.push('header keys');
        findings.push(
          ag012Finding({
            severity: 'high',
            confidence: 'high',
            file: server.sourceFile,
            path: server.jsonPath,
            evidence: `changed: ${changed.join(', ')}`,
            detailEn: `Server "${server.name}" changed since the baseline (${changed.join(', ')}).`,
            detailJa: `サーバー「${server.name}」がベースラインから変更されています（${changed.join('、')}）。`,
          }),
        );
      }
    }
  }

  for (const e of baseline.entries) {
    if (seen.has(e.key)) continue;
    const sep = e.key.lastIndexOf('::');
    findings.push(
      ag012Finding({
        severity: 'info',
        confidence: 'high',
        file: e.key.slice(0, sep),
        detailEn: `Server "${e.key.slice(sep + 2)}" was removed since the baseline.`,
        detailJa: `サーバー「${e.key.slice(sep + 2)}」はベースラインから削除されています。`,
      }),
    );
  }
  return findings;
}

/** Findings for `scan --compare-baseline`. Missing baseline is an info note. */
export async function baselineFindings(cwd: string, targets: ScanTarget[]): Promise<Finding[]> {
  const baseline = await loadBaseline(cwd);
  if (!baseline) {
    return [
      ag012Finding({
        severity: 'info',
        confidence: 'high',
        detailEn: 'No baseline found. Create one with "aster-guard baseline create".',
        detailJa:
          'ベースラインが見つかりません。「aster-guard baseline create」で作成してください。',
      }),
    ];
  }
  return compareWithBaseline(targets, baseline);
}
