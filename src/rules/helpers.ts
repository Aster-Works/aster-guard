import type { Confidence, Finding, Severity } from '../types/finding.js';
import type { NormalizedServer, ScanTarget } from '../types/config.js';
import { redactText } from '../core/redaction.js';
import type { RuleMeta } from './rule.js';

export interface StringSite {
  value: string;
  /** Where the string lives: dotted JSON path, or `KEY (line N)` for env files. */
  path: string;
  /** Last key name leading to this value (env var name for env files). */
  keyName: string;
  server?: NormalizedServer;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function walkStrings(
  node: unknown,
  prefix: string,
  keyName: string,
  out: StringSite[],
  server: NormalizedServer | undefined,
  depth: number,
): void {
  if (depth > 8) return;
  if (typeof node === 'string') {
    out.push({ value: node, path: prefix, keyName, server });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((item, i) =>
      walkStrings(item, `${prefix}[${i}]`, keyName, out, server, depth + 1),
    );
    return;
  }
  if (isRecord(node)) {
    for (const [k, v] of Object.entries(node)) {
      walkStrings(v, prefix ? `${prefix}.${k}` : k, k, out, server, depth + 1);
    }
  }
}

/**
 * Every string value worth inspecting in a target.
 *
 * For `mcp-config` files only the `mcpServers` entries are walked: files like
 * `~/.claude.json` also hold unrelated data (e.g. prompt history) that must
 * not trigger security rules.
 */
export function collectSites(target: ScanTarget): StringSite[] {
  if (target.kind === 'env-file') {
    return target.envVars.map((v) => ({
      value: v.value,
      path: `${v.key} (line ${v.line})`,
      keyName: v.key,
    }));
  }
  const out: StringSite[] = [];
  if (target.kind === 'claude-settings') {
    walkStrings(target.json, '', '', out, undefined, 0);
    return out;
  }
  for (const server of target.servers) {
    walkStrings(server.rawEntry, server.jsonPath, server.name, out, server, 0);
  }
  return out;
}

/** The joined command line a client would execute for this server. */
export function commandLine(server: NormalizedServer): string {
  return [server.command ?? '', ...server.args].join(' ').trim();
}

/**
 * Scan units for pattern rules: one synthetic unit per server holding the
 * joined command line (so `command: "rm", args: ["-rf", "/"]` is seen as
 * `rm -rf /`), plus all other string sites. Raw `command`/`args` sites are
 * dropped to avoid double counting.
 */
export function scanUnits(target: ScanTarget): StringSite[] {
  const sites = collectSites(target);
  const units: StringSite[] = [];
  for (const server of target.servers) {
    const cl = commandLine(server);
    if (cl) {
      units.push({ value: cl, path: `${server.jsonPath} (command)`, keyName: 'command', server });
    }
  }
  const filtered = sites.filter(
    (s) => !(s.server && (s.keyName === 'command' || /\.args\[\d+\]$/.test(s.path))),
  );
  return [...units, ...filtered];
}

export function truncate(text: string, max = 160): string {
  return text.length <= max ? text : text.slice(0, max - 1) + '…';
}

export interface FindingOptions {
  target: ScanTarget;
  confidence: Confidence;
  path?: string;
  /** Raw evidence; it is always redacted and truncated before being stored. */
  evidence?: string;
  severity?: Severity;
  detailEn?: string;
  detailJa?: string;
  explanationEn?: string;
  explanationJa?: string;
}

/**
 * Strings under `permissions.allow` / `permissions.ask` in Claude settings
 * are permission patterns the user already approved themselves — not content
 * supplied by a third-party MCP server. They are still surfaced, but as
 * info-level notes so a user's own allowlist doesn't tank the score.
 */
const USER_APPROVED_PERMISSION_PATH = /(^|\.)permissions\.(allow|ask)\[/;

export function makeFinding(rule: RuleMeta, opts: FindingOptions): Finding {
  const evidence = opts.evidence === undefined ? undefined : truncate(redactText(opts.evidence));
  let explanationEn = opts.explanationEn ?? rule.explanationEn;
  let explanationJa = opts.explanationJa ?? rule.explanationJa;
  const userApproved = opts.path !== undefined && USER_APPROVED_PERMISSION_PATH.test(opts.path);
  if (userApproved) {
    explanationEn +=
      ' Found in a permission rule you approved yourself, so it is reported as info only.';
    explanationJa +=
      ' これはあなた自身が承認したpermissionsルール内での検出のため、情報レベルとして報告しています。';
  }
  return {
    ruleId: rule.id,
    title: rule.nameEn,
    severity: userApproved ? 'info' : (opts.severity ?? rule.severity),
    confidence: userApproved ? 'low' : opts.confidence,
    file: opts.target.file,
    path: opts.path,
    evidence,
    redactedEvidence: evidence,
    explanationJa: opts.detailJa ? `${explanationJa}（${opts.detailJa}）` : explanationJa,
    explanationEn: opts.detailEn ? `${explanationEn} (${opts.detailEn})` : explanationEn,
    recommendationJa: rule.recommendationJa,
    recommendationEn: rule.recommendationEn,
  };
}
