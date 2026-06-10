import os from 'node:os';
import type { Rule } from './rule.js';
import { collectSites, commandLine, makeFinding } from './helpers.js';

const BROAD_EXACT = new Set([
  '/',
  '~',
  '~/',
  'C:\\',
  'C:/',
  '/Users',
  '/Users/',
  '/home',
  '/home/',
]);

const BROAD_RE: ReadonlyArray<RegExp> = [
  /^~\/Documents\/?$/i,
  /^~\/Desktop\/?$/i,
  /(^|[/\\])\.\.[/\\]\.\.([/\\]|$)/,
];

function isBroadPath(value: string): boolean {
  const v = value.trim();
  if (BROAD_EXACT.has(v)) return true;
  if (v === os.homedir() || v === os.homedir() + '/') return true;
  return BROAD_RE.some((re) => re.test(v));
}

export const AG006: Rule = {
  id: 'AG-006',
  nameEn: 'Overbroad Filesystem Access',
  nameJa: '過度に広いファイルシステムアクセス',
  severity: 'medium',
  explanationEn:
    'An MCP server is given access to a very broad path (e.g. "/", "~", or your whole user folder). If the server misbehaves or is compromised, everything under that path is exposed.',
  explanationJa:
    'MCPサーバーに非常に広い範囲のパス（例：「/」「~」、ユーザーフォルダ全体）へのアクセスが与えられています。サーバーが悪用された場合、その範囲のすべてのファイルが危険にさらされます。',
  recommendationEn:
    'Narrow the path to the specific project directory the server actually needs, e.g. "./src" or the project root.',
  recommendationJa:
    'アクセス範囲を、実際に必要なプロジェクトディレクトリ（例：「./src」やプロジェクトルート）まで絞り込んでください。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];
    for (const site of collectSites(target)) {
      if (!isBroadPath(site.value)) continue;
      // A filesystem-style server with a broad root is the worst case.
      const fsContext =
        site.server !== undefined &&
        /file[-_]?system|server-filesystem/i.test(
          commandLine(site.server) + ' ' + site.server.name,
        );
      findings.push(
        makeFinding(AG006, {
          target,
          severity: fsContext ? 'high' : 'medium',
          confidence: fsContext ? 'high' : 'medium',
          path: site.path,
          evidence: site.value,
        }),
      );
    }
    return findings;
  },
};
