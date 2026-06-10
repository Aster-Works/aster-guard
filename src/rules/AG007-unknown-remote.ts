import type { Rule } from './rule.js';
import { makeFinding } from './helpers.js';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

export const AG007: Rule = {
  id: 'AG-007',
  nameEn: 'Remote MCP Server with Unknown Origin',
  nameJa: '出所が確認されていないリモートMCPサーバー',
  severity: 'medium',
  explanationEn:
    'This configuration connects to a remote MCP server. Remote servers can change their behavior at any time without you noticing, so the origin must be one you trust.',
  explanationJa:
    'リモートのMCPサーバーへ接続する設定です。リモートサーバーは提供側の都合でいつでも挙動を変えられるため、確実に信頼できる提供元かどうかの確認が必要です。',
  recommendationEn:
    'Verify who operates this URL and why you trust it. Prefer HTTPS, and remove the entry if you no longer use it.',
  recommendationJa:
    'このURLの運営者が誰か、信頼できる根拠は何かを確認してください。必ずHTTPSを使い、使っていない接続先は設定から削除しましょう。',
  check(target) {
    const findings = [];
    for (const server of target.servers) {
      if (!server.url) continue;
      let host = '';
      let insecure = false;
      try {
        const parsed = new URL(server.url);
        host = parsed.hostname.toLowerCase();
        insecure = parsed.protocol === 'http:';
      } catch {
        continue; // not a parsable URL; nothing to assess
      }
      if (LOCAL_HOSTS.has(host)) continue;
      findings.push(
        makeFinding(AG007, {
          target,
          confidence: insecure ? 'high' : 'medium',
          path: `${server.jsonPath}.url`,
          evidence: server.url,
          detailEn: insecure ? 'plaintext HTTP, not encrypted' : undefined,
          detailJa: insecure ? '暗号化されないHTTP接続です' : undefined,
        }),
      );
    }
    return findings;
  },
};
