import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PATTERNS: ReadonlyArray<{ re: RegExp; label: string; confidence: Confidence }> = [
  {
    re: /~\/\.ssh\b|[/\\]\.ssh\b|\bid_rsa\b|\bid_ed25519\b/,
    label: 'SSH keys',
    confidence: 'high',
  },
  { re: /\.aws[/\\]credentials/, label: 'AWS credentials', confidence: 'high' },
  { re: /\.git-credentials/, label: 'Git credentials', confidence: 'high' },
  { re: /(^|[\s"'=:/])\.npmrc\b/, label: '.npmrc', confidence: 'medium' },
  { re: /(^|[\s"'=:/])\.pypirc\b/, label: '.pypirc', confidence: 'medium' },
  { re: /~\/\.config\b/, label: '~/.config', confidence: 'medium' },
  { re: /(^|[\s"'=:(/])\.env(\.[A-Za-z0-9_-]+)?\b/, label: '.env files', confidence: 'medium' },
];

export const AG002: Rule = {
  id: 'AG-002',
  nameEn: 'Sensitive File Exfiltration Pattern',
  nameJa: '機微ファイルへのアクセス・持ち出しパターン',
  severity: 'critical',
  explanationEn:
    'The configuration references sensitive local files such as SSH keys, cloud credentials, or .env files. An MCP server with access to these can leak your credentials.',
  explanationJa:
    'SSH鍵・クラウド認証情報・.envファイルなど、機微なローカルファイルへの参照が含まれています。これらにアクセスできるMCPサーバーは、あなたの認証情報を外部に漏らす危険があります。',
  recommendationEn:
    'Remove these references, or scope the server to a safe directory. Never give an untrusted MCP server access to key files or .env files.',
  recommendationJa:
    'この参照を削除するか、サーバーのアクセス範囲を安全なディレクトリに限定してください。信頼できないMCPサーバーに鍵ファイルや.envへのアクセスを与えてはいけません。',
  check(target) {
    if (target.kind === 'env-file') return [];
    const findings = [];
    for (const unit of scanUnits(target)) {
      // Claude permission deny rules legitimately mention .env etc. — that is
      // a protection, not an exposure.
      if (/(^|\.)deny\b/i.test(unit.path)) continue;
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG002, {
            target,
            confidence: hit.confidence,
            path: unit.path,
            evidence: unit.value,
            detailEn: hit.label,
            detailJa: hit.label,
          }),
        );
      }
    }
    return findings;
  },
};
