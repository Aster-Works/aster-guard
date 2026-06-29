import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import type { ScanTarget } from '../types/config.js';
import { makeFinding, scanUnits } from './helpers.js';

/**
 * Environment variable names that the OS or language runtime reads at startup
 * before any user code runs, giving the ability to inject arbitrary code or
 * libraries into the MCP server process (or into the host if the server
 * spawns child processes with inherited env).
 */
const INJECTORS: ReadonlyArray<{ re: RegExp; label: string; confidence: Confidence }> = [
  // Node.js: run arbitrary code in every node process
  { re: /\bNODE_OPTIONS\b/, label: 'NODE_OPTIONS', confidence: 'high' },
  // Linux dynamic linker: preload a shared library into every exec
  { re: /\bLD_PRELOAD\b/, label: 'LD_PRELOAD', confidence: 'high' },
  { re: /\bLD_LIBRARY_PATH\b/, label: 'LD_LIBRARY_PATH', confidence: 'medium' },
  // macOS dynamic linker equivalents
  { re: /\bDYLD_INSERT_LIBRARIES\b/, label: 'DYLD_INSERT_LIBRARIES', confidence: 'high' },
  { re: /\bDYLD_LIBRARY_PATH\b/, label: 'DYLD_LIBRARY_PATH', confidence: 'medium' },
  // Python: prepend arbitrary code to every python invocation
  { re: /\bPYTHONSTARTUP\b/, label: 'PYTHONSTARTUP', confidence: 'high' },
  // Perl: extra code run before the script
  { re: /\bPERL5OPT\b/, label: 'PERL5OPT', confidence: 'high' },
  // Ruby: inject code via site_ruby / lib path
  { re: /\bRUBYOPT\b/, label: 'RUBYOPT', confidence: 'medium' },
  // Java: agent and class-path manipulation
  { re: /\bJAVA_TOOL_OPTIONS\b/, label: 'JAVA_TOOL_OPTIONS', confidence: 'high' },
  { re: /\b_JAVA_OPTIONS\b/, label: '_JAVA_OPTIONS', confidence: 'high' },
  // PATH prepend in env values — classic trojan horse
  { re: /\bPATH\s*=\s*(?:\/tmp|\/var\/tmp|\.\/|~\/)/, label: 'PATH (suspicious prefix)', confidence: 'medium' },
];

/** True when the env key itself is a known injector (env-file mode). */
function isInjectorKey(key: string): { label: string; confidence: Confidence } | undefined {
  const k = key.trim();
  for (const inj of INJECTORS) {
    if (inj.re.test(k)) return { label: inj.label, confidence: inj.confidence };
  }
  return undefined;
}

export const AG013: Rule = {
  id: 'AG-013',
  nameEn: 'Runtime Environment Variable Injection',
  nameJa: 'ランタイム環境変数インジェクション',
  severity: 'critical',
  explanationEn:
    'An environment variable that the OS or language runtime reads at process startup (e.g. NODE_OPTIONS, LD_PRELOAD, DYLD_INSERT_LIBRARIES) is present in the MCP server config. ' +
    'Setting these variables allows injecting arbitrary code or shared libraries into every process the server spawns, before any application code runs.',
  explanationJa:
    'OS・言語ランタイムが起動時に読み込む環境変数（例：NODE_OPTIONS、LD_PRELOAD、DYLD_INSERT_LIBRARIES）がMCPサーバー設定に含まれています。' +
    'これらを設定されると、サーバーが起動するすべてのプロセスに任意のコードや共有ライブラリを注入できます。アプリケーションコードが実行される前に、です。',
  recommendationEn:
    'Remove these environment variable overrides from the MCP config. If they are required, verify the value set is safe, and restrict the scope to the minimum necessary.',
  recommendationJa:
    'MCP設定からこれらの環境変数の上書きを削除してください。どうしても必要な場合は、設定値が安全であることを確認し、影響範囲を最小限に絞り込んでください。',
  check(target: ScanTarget) {
    const findings = [];

    // In env-file mode: flag the key itself if it is an injector.
    if (target.kind === 'env-file') {
      for (const unit of scanUnits(target)) {
        const hit = isInjectorKey(unit.keyName);
        if (hit) {
          findings.push(
            makeFinding(AG013, {
              target,
              confidence: hit.confidence,
              path: unit.path,
              evidence: `${unit.keyName}=${unit.value}`,
              detailEn: hit.label,
              detailJa: hit.label,
            }),
          );
        }
      }
      return findings;
    }

    // In MCP config mode: check env blocks of each server.
    for (const server of target.servers) {
      for (const [key, value] of Object.entries(server.env)) {
        // Check by key name first (most reliable).
        const byKey = isInjectorKey(key);
        if (byKey) {
          findings.push(
            makeFinding(AG013, {
              target,
              confidence: byKey.confidence,
              path: `${server.jsonPath}.env.${key}`,
              evidence: `${key}=${value}`,
              detailEn: byKey.label,
              detailJa: byKey.label,
            }),
          );
          continue;
        }
        // Also scan the value for references to injector vars (e.g. in
        // descriptions or inline shell strings that set env).
        for (const inj of INJECTORS) {
          if (inj.re.test(value)) {
            findings.push(
              makeFinding(AG013, {
                target,
                confidence: 'medium',
                path: `${server.jsonPath}.env.${key}`,
                evidence: `${key}=${value}`,
                detailEn: inj.label,
                detailJa: inj.label,
              }),
            );
            break;
          }
        }
      }
    }

    // Also scan all string units for inline env-set patterns in commands /
    // descriptions, e.g. "NODE_OPTIONS=--require=./evil.js node server.js".
    for (const unit of scanUnits(target)) {
      // Skip env blocks — already covered above.
      if (/\.env\./.test(unit.path)) continue;
      for (const inj of INJECTORS) {
        if (inj.re.test(unit.value)) {
          findings.push(
            makeFinding(AG013, {
              target,
              confidence: inj.confidence,
              path: unit.path,
              evidence: unit.value,
              detailEn: inj.label,
              detailJa: inj.label,
            }),
          );
          break;
        }
      }
    }

    return findings;
  },
};
