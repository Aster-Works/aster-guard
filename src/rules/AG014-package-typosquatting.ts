import type { Rule } from './rule.js';
import { commandLine, makeFinding } from './helpers.js';

/**
 * Well-known MCP / Claude-Code package names that attackers frequently
 * typosquat.  Each entry holds:
 *   - canonical:  the legitimate package (or bare name for `npx`)
 *   - variants:   regex that matches known-bad lookalikes
 *   - label:      shown in the finding detail
 */
const SQUAT_TARGETS: ReadonlyArray<{
  canonical: string;
  variants: RegExp;
  label: string;
}> = [
  {
    canonical: '@modelcontextprotocol/server-github',
    // gith[uo]?b catches: githb (vowel missing), githob (wrong vowel), github (correct, excluded by canonical check)
    variants:
      /@modelcontextprotocol\/server[-_]?gith[uo]?b|mcp[-_]?server[-_]?github(?!\.com)|modelcontextprot(?!ocol)/i,
    label: '@modelcontextprotocol/server-github',
  },
  {
    canonical: '@modelcontextprotocol/server-filesystem',
    variants:
      /@modelcontextprotocol\/server[-_]?file[-_]?sys(?:tem)?|mcp[-_]?server[-_]?filesystem/i,
    label: '@modelcontextprotocol/server-filesystem',
  },
  {
    canonical: '@modelcontextprotocol/server-brave-search',
    variants: /@modelcontextprotocol\/server[-_]?brave[-_]?serach|mcp[-_]?brave[-_]?search/i,
    label: '@modelcontextprotocol/server-brave-search',
  },
  {
    canonical: '@modelcontextprotocol/server-postgres',
    variants:
      /mcp[-_]?server[-_]?postgres|@modelcontextprotocol\/server[-_]?postgress/i,
    label: '@modelcontextprotocol/server-postgres',
  },
  {
    canonical: '@modelcontextprotocol/server-slack',
    variants: /mcp[-_]?server[-_]?slack|@modelcontextprotocol\/server[-_]?slaak/i,
    label: '@modelcontextprotocol/server-slack',
  },
  // Scope-spoofing: fake @modelcontextprotocol scope
  {
    canonical: '@modelcontextprotocol/',
    variants: /@modelcontextprot[^o]col\/|@model[-_]context[-_]protocol\//i,
    label: '@modelcontextprotocol scope',
  },
  // Hyphen/underscore swap on common npx commands used in the wild
  {
    canonical: 'mcp-server-git',
    variants: /\bncp[-_]server[-_]git\b|\bmcp[-_]server[-_]gitt\b/i,
    label: 'mcp-server-git',
  },
];

/**
 * Extract package names from a command line.
 * Handles patterns like:
 *   npx @scope/name@1.2.3
 *   npx -y @scope/name
 *   node_modules/.bin/name
 *   node /path/to/name
 */
function extractPackageTokens(cl: string): string[] {
  const tokens: string[] = [];
  // npx [flags] <pkg>
  const npxMatch = cl.match(/\bnpx\b\s+(?:-[yY\w]+\s+)*(@?[\w/@.-]+)/);
  if (npxMatch?.[1]) tokens.push(npxMatch[1]);
  // npm exec / pnpm exec / yarn dlx
  const execMatch = cl.match(/\b(?:npm\s+exec|pnpm\s+exec|yarn\s+dlx)\b\s+(@?[\w/@.-]+)/);
  if (execMatch?.[1]) tokens.push(execMatch[1]);
  // All @scope/name tokens
  const atTokens = cl.match(/@[\w-]+\/[\w.-]+/g) ?? [];
  tokens.push(...atTokens);
  return tokens;
}

export const AG014: Rule = {
  id: 'AG-014',
  nameEn: 'Package Name Typosquatting',
  nameJa: 'パッケージ名のタイポスクワッティング',
  severity: 'critical',
  explanationEn:
    'The MCP server command uses a package name that looks like a typo of a well-known, trusted package. ' +
    'Typosquatted packages are a common supply-chain attack: they often contain malware but appear safe at a glance.',
  explanationJa:
    'MCPサーバーのコマンドに、よく知られた信頼済みパッケージのタイポ（誤字）に見えるパッケージ名が使われています。' +
    'タイポスクワッティングは一般的なサプライチェーン攻撃の手口で、一見無害に見えてマルウェアを含むことがあります。',
  recommendationEn:
    'Double-check the exact package name against the official source. If in doubt, look up the package on npmjs.com and verify its download count, publisher, and repository link.',
  recommendationJa:
    '公式ソースと照合してパッケージ名を正確に確認してください。不明な場合はnpmjs.comでパッケージを検索し、ダウンロード数・公開者・リポジトリリンクを確かめてください。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];

    for (const server of target.servers) {
      const cl = commandLine(server);
      if (!cl) continue;

      const tokens = extractPackageTokens(cl);

      for (const token of tokens) {
        for (const sq of SQUAT_TARGETS) {
          // Skip if this IS the canonical package (strip version suffix first).
          const bare = token.replace(/@[\d.]+$/, '');
          if (bare === sq.canonical || bare.startsWith(sq.canonical + '/')) continue;

          if (sq.variants.test(token)) {
            findings.push(
              makeFinding(AG014, {
                target,
                confidence: 'high',
                path: `${server.jsonPath} (command)`,
                evidence: cl,
                detailEn: `looks like a typosquat of "${sq.label}"`,
                detailJa: `「${sq.label}」のタイポスクワットの疑いがあります`,
              }),
            );
            break;
          }
        }
      }
    }

    return findings;
  },
};
