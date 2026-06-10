import fs from 'node:fs/promises';
import type { Finding } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';
import {
  isSecretKeyName,
  looksLikeSecretValue,
  matchSecretValue,
  redactSecret,
} from './redaction.js';
import type { Locale } from '../i18n/index.js';

export interface SecretMove {
  file: string;
  /** JSON path segments to the secret value (real object keys, not dotted). */
  segments: string[];
  keyName: string;
  envVarName: string;
  redactedValue: string;
}

export interface HardenAdvice {
  ruleId: string;
  en: string;
  ja: string;
}

export interface HardenPlan {
  moves: SecretMove[];
  advice: HardenAdvice[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const GENERIC_KEY_NAMES = new Set([
  'TOKEN',
  'KEY',
  'APIKEY',
  'API_KEY',
  'SECRET',
  'PASSWORD',
  'AUTH',
  'AUTHORIZATION',
]);

function toEnvVarName(segments: string[], keyName: string, used: Set<string>): string {
  const sanitize = (s: string) =>
    s
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
  let name = sanitize(keyName);
  if (name.length < 4 || GENERIC_KEY_NAMES.has(name)) {
    const idx = segments.indexOf('mcpServers');
    const serverName = idx >= 0 ? segments[idx + 1] : undefined;
    if (serverName) name = `${sanitize(serverName)}_${name}`;
  }
  let unique = name;
  let counter = 2;
  while (used.has(unique)) unique = `${name}_${counter++}`;
  used.add(unique);
  return unique;
}

const ADVICE_BY_RULE: ReadonlyArray<HardenAdvice> = [
  {
    ruleId: 'AG-003',
    en: 'Replace shell-string launches (e.g. `bash -c "..."`) with a direct command and explicit args.',
    ja: 'シェル文字列での起動（例: `bash -c "..."`）を、直接コマンド＋明示的な引数に置き換えてください。',
  },
  {
    ruleId: 'AG-004',
    en: 'Remove `curl | bash`-style installers; download, review, then run a pinned version.',
    ja: '`curl | bash` 形式のインストールをやめ、ダウンロード・内容確認のうえバージョン固定で実行してください。',
  },
  {
    ruleId: 'AG-006',
    en: 'Narrow broad filesystem paths to the specific directories the server needs.',
    ja: '広すぎるファイルシステムパスを、サーバーが実際に必要とするディレクトリに絞ってください。',
  },
  {
    ruleId: 'AG-007',
    en: 'Verify each remote MCP URL, prefer HTTPS, and remove endpoints you do not use.',
    ja: 'リモートMCPのURLは提供元を確認し、HTTPSを使い、不要な接続先は削除してください。',
  },
];

/**
 * Build a hardening plan: concrete secret→env-var moves plus advice derived
 * from the scan findings. Building the plan never modifies anything.
 */
export function buildHardenPlan(targets: ScanTarget[], findings: Finding[]): HardenPlan {
  const moves: SecretMove[] = [];
  const usedNames = new Set<string>();

  for (const target of targets) {
    if (target.kind === 'env-file' || target.parseError || target.json === undefined) continue;
    const walk = (node: unknown, segments: string[], depth: number): void => {
      if (depth > 8) return;
      if (!isRecord(node)) return;
      for (const [key, value] of Object.entries(node)) {
        if (typeof value === 'string') {
          // Only rewrite inside mcpServers blocks (or anywhere in settings files);
          // other JSON content is left untouched.
          const inScope = target.kind === 'claude-settings' || segments.includes('mcpServers');
          if (!inScope) continue;
          const secret =
            matchSecretValue(value) !== undefined ||
            (isSecretKeyName(key) && looksLikeSecretValue(value));
          if (secret) {
            moves.push({
              file: target.file,
              segments: [...segments, key],
              keyName: key,
              envVarName: toEnvVarName([...segments, key], key, usedNames),
              redactedValue: redactSecret(value),
            });
          }
        } else if (isRecord(value)) {
          walk(value, [...segments, key], depth + 1);
        }
      }
    };
    walk(target.json, [], 0);
  }

  const foundRuleIds = new Set(findings.map((f) => f.ruleId));
  const advice = ADVICE_BY_RULE.filter((a) => foundRuleIds.has(a.ruleId));
  return { moves, advice };
}

export interface HardenWriteResult {
  file: string;
  backupPath: string;
  envVarNames: string[];
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

/**
 * Apply the secret→env-var moves. For every modified file a timestamped
 * backup is created first. Only call this when the user passed --write.
 */
export async function applyHardenPlan(plan: HardenPlan): Promise<HardenWriteResult[]> {
  const byFile = new Map<string, SecretMove[]>();
  for (const move of plan.moves) {
    const list = byFile.get(move.file) ?? [];
    list.push(move);
    byFile.set(move.file, list);
  }

  const results: HardenWriteResult[] = [];
  for (const [file, moves] of byFile) {
    const raw = await fs.readFile(file, 'utf8');
    const json: unknown = JSON.parse(raw);
    const applied: string[] = [];
    for (const move of moves) {
      let node: unknown = json;
      for (const seg of move.segments.slice(0, -1)) {
        node = isRecord(node) ? node[seg] : undefined;
      }
      const lastKey = move.segments[move.segments.length - 1];
      if (isRecord(node) && lastKey !== undefined && typeof node[lastKey] === 'string') {
        node[lastKey] = `\${${move.envVarName}}`;
        applied.push(move.envVarName);
      }
    }
    if (applied.length === 0) continue;
    const backupPath = `${file}.bak-${timestamp()}`;
    await fs.copyFile(file, backupPath);
    // Atomic replace: a failed write can never leave the original truncated.
    const tmpPath = `${file}.tmp-${timestamp()}`;
    await fs.writeFile(tmpPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
    await fs.rename(tmpPath, file);
    results.push({ file, backupPath, envVarNames: applied });
  }
  return results;
}

/** Render the preview shown by `aster-guard harden` (read-only by default). */
export function renderHardenPreview(plan: HardenPlan, locale: Locale): string {
  const ja = locale === 'ja';
  const lines: string[] = [];
  lines.push(
    ja
      ? '== Aster Guard 強化プラン（プレビュー） =='
      : '== Aster Guard Hardening Plan (preview) ==',
  );
  lines.push(
    ja
      ? 'このコマンドは既定では何も変更しません。適用するには --write を付けてください（適用前にバックアップを作成します）。'
      : 'By default nothing is modified. Pass --write to apply (a backup is created first).',
  );
  lines.push('');
  if (plan.moves.length > 0) {
    lines.push(ja ? '環境変数へ移すべき秘密情報:' : 'Secrets to move to environment variables:');
    for (const m of plan.moves) {
      lines.push(`  - ${m.file}`);
      lines.push(`      ${m.segments.join('.')}: ${m.redactedValue} -> \${${m.envVarName}}`);
    }
    lines.push('');
    lines.push(
      ja
        ? '適用後は、シェルの環境（例: ~/.zshrc）で上記の環境変数を設定してください。'
        : 'After applying, set those environment variables in your shell (e.g. ~/.zshrc).',
    );
    lines.push('');
  } else {
    lines.push(
      ja ? '移動が必要な秘密情報は見つかりませんでした。' : 'No hardcoded secrets to move.',
    );
    lines.push('');
  }
  if (plan.advice.length > 0) {
    lines.push(ja ? 'その他の推奨対応:' : 'Additional recommendations:');
    for (const a of plan.advice) lines.push(`  - [${a.ruleId}] ${ja ? a.ja : a.en}`);
    lines.push('');
  }
  return lines.join('\n');
}
