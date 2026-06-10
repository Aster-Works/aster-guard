/**
 * Secret redaction helpers.
 *
 * Aster Guard must never print a full secret value anywhere: not in the
 * terminal, not in JSON or Markdown reports, and not over MCP. When unsure,
 * redact more aggressively.
 */

export interface SecretPattern {
  label: string;
  re: RegExp;
}

/** Patterns for well-known secret token formats. Order matters (most specific first). */
export const SECRET_VALUE_PATTERNS: readonly SecretPattern[] = [
  { label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/ },
  { label: 'OpenAI-style API key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { label: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'Private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: 'Bearer token', re: /\bBearer\s+[A-Za-z0-9._+/=-]{16,}/ },
];

const KNOWN_PREFIXES: readonly RegExp[] = [
  /^sk-ant-/i,
  /^sk-/,
  /^github_pat_/,
  /^gh[pousr]_/,
  /^xox[baprs]-/,
  /^AKIA/,
  /^AIza/,
  /^Bearer\s+/i,
];

/**
 * Redact a single secret value, keeping only a recognizable prefix and the
 * last 4 characters: `sk-ant-api03-…` -> `sk-ant-********3456`.
 */
export function redactSecret(value: string): string {
  if (!value) return '';
  if (value.length <= 8) return '*'.repeat(Math.max(value.length, 4));

  let prefix = '';
  for (const re of KNOWN_PREFIXES) {
    const m = re.exec(value);
    if (m) {
      prefix = m[0];
      break;
    }
  }
  const tail = value.length - prefix.length > 8 ? value.slice(-4) : '';
  const maskedLen = value.length - prefix.length - tail.length;
  return prefix + '*'.repeat(Math.max(maskedLen, 4)) + tail;
}

/** Replace every recognizable secret token inside a free-form text. */
export function redactText(text: string): string {
  let out = text;
  for (const p of SECRET_VALUE_PATTERNS) {
    const flags = p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g';
    out = out.replace(new RegExp(p.re.source, flags), (m) => redactSecret(m));
  }
  return out;
}

/** Match a value against the known secret token formats. */
export function matchSecretValue(value: string): SecretPattern | undefined {
  return SECRET_VALUE_PATTERNS.find((p) => new RegExp(p.re.source, p.re.flags).test(value));
}

const SECRET_KEY_NAME =
  /(api[-_]?key|apikey|secret|token|passwd|password|credential|private[-_]?key|access[-_]?key|client[-_]?secret|auth)/i;

const PLACEHOLDER_VALUE =
  /^(<[^>]*>|x+|\*+|\.+|(your|my|sample|example|dummy|fake|test|changeme|change-me|placeholder|redacted|none|null|undefined|true|false)[-_a-z0-9]*)$/i;

/** Whether a config key name suggests its value is a credential. */
export function isSecretKeyName(key: string): boolean {
  return SECRET_KEY_NAME.test(key);
}

/**
 * Heuristic for "this value looks like a real credential" (vs. a placeholder
 * or an environment-variable reference like `${GITHUB_TOKEN}`).
 */
export function looksLikeSecretValue(value: string): boolean {
  if (value.length < 8) return false;
  if (/\s/.test(value)) return false;
  if (value.includes('${') || /^\$[A-Z_][A-Z0-9_]*$/i.test(value)) return false;
  if (PLACEHOLDER_VALUE.test(value)) return false;
  return (/[A-Za-z]/.test(value) && /[0-9]/.test(value)) || value.length >= 24;
}
