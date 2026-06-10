import {
  isSecretKeyName,
  looksLikeSecretValue,
  matchSecretValue,
  redactSecret,
} from '../core/redaction.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const ENV_FILE_DETAIL_EN =
  'found in a .env file — that is the right place for secrets, but make sure the file is gitignored and never handed to an MCP server';
const ENV_FILE_DETAIL_JA =
  '.envファイル内での検出です。秘密情報の置き場所としては正しいですが、gitignoreされているか、MCPサーバーに渡っていないかを確認してください';

export const AG005: Rule = {
  id: 'AG-005',
  nameEn: 'Hardcoded Secret in Config',
  nameJa: '設定ファイルにハードコードされた秘密情報',
  severity: 'critical',
  explanationEn:
    'An API key, token, or password appears to be written directly in a configuration file. Anyone (or any tool) that can read this file gets the credential, and it is easy to leak via git or backups.',
  explanationJa:
    'APIキー・トークン・パスワードと思われる値が設定ファイルに直接書き込まれています。このファイルを読める人やツールはすべてこの認証情報を入手でき、gitやバックアップ経由で漏えいしやすい状態です。',
  recommendationEn:
    'Move the secret to an environment variable and reference it (e.g. "${GITHUB_TOKEN}"). Rotate the credential if this file has ever been shared or committed.',
  recommendationJa:
    '秘密情報は環境変数に移し、設定からは参照（例：「${GITHUB_TOKEN}」）にしてください。このファイルを共有・コミットしたことがある場合は、キーの再発行（ローテーション）も行いましょう。',
  check(target) {
    const findings = [];
    const isEnvFile = target.kind === 'env-file';
    for (const unit of scanUnits(target)) {
      const known = matchSecretValue(unit.value);
      const byName = !known && isSecretKeyName(unit.keyName) && looksLikeSecretValue(unit.value);
      if (!known && !byName) continue;
      findings.push(
        makeFinding(AG005, {
          target,
          // Secrets inside .env files are normal practice; report as info so
          // they don't tank the score, but still surface (and redact) them.
          severity: isEnvFile ? 'info' : 'critical',
          confidence: known ? 'high' : 'medium',
          path: unit.path,
          evidence: `${unit.keyName}=${redactSecret(unit.value)}`,
          detailEn: isEnvFile ? ENV_FILE_DETAIL_EN : known?.label,
          detailJa: isEnvFile ? ENV_FILE_DETAIL_JA : known?.label,
        }),
      );
    }
    return findings;
  },
};
