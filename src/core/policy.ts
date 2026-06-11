import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';

/**
 * Team policy file: `.aster-guard/policy.json` in the scan root. Commit it to
 * share allowlists and thresholds across a team.
 */
export interface AsterGuardPolicy {
  /** Remote MCP hosts AG-007 should trust. Supports "*.domain" wildcards. */
  allowedRemoteHosts?: string[];
  /** Rule ids (e.g. "AG-008") whose findings are suppressed entirely. */
  ignoreRules?: string[];
  /** Default exit-code threshold for `scan` (CLI --fail-on overrides this). */
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'never';
}

const PolicySchema = z
  .object({
    allowedRemoteHosts: z.array(z.string()).optional(),
    ignoreRules: z.array(z.string()).optional(),
    failOn: z.enum(['critical', 'high', 'medium', 'low', 'info', 'never']).optional(),
  })
  .strict();

export function policyFilePath(cwd: string): string {
  return path.join(cwd, '.aster-guard', 'policy.json');
}

export interface PolicyLoadResult {
  policy: AsterGuardPolicy;
  /** Human-readable problem with the policy file, if any. */
  error?: string;
}

/** Load the policy file. A missing file is fine; a broken one is reported. */
export async function loadPolicy(cwd: string): Promise<PolicyLoadResult> {
  const file = policyFilePath(cwd);
  let raw: string;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch {
    return { policy: {} };
  }
  try {
    return { policy: PolicySchema.parse(JSON.parse(raw)) };
  } catch (err) {
    const message =
      err instanceof z.ZodError
        ? err.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')
        : err instanceof Error
          ? err.message
          : String(err);
    return { policy: {}, error: `Invalid policy file ${file}: ${message}` };
  }
}

/** Case-insensitive host match; "*.corp.dev" matches any subdomain. */
export function hostMatches(host: string, patterns: readonly string[] | undefined): boolean {
  if (!patterns || patterns.length === 0) return false;
  const h = host.toLowerCase();
  return patterns.some((p) => {
    const pat = p.toLowerCase().trim();
    if (pat === '') return false;
    if (pat.startsWith('*.')) return h.endsWith(pat.slice(1));
    return h === pat;
  });
}

/** Scaffold a policy file. Never overwrites an existing one. */
export async function initPolicy(cwd: string): Promise<{ file: string; created: boolean }> {
  const file = policyFilePath(cwd);
  try {
    await fs.access(file);
    return { file, created: false };
  } catch {
    // does not exist — create it
  }
  await fs.mkdir(path.dirname(file), { recursive: true });
  const template: AsterGuardPolicy = { allowedRemoteHosts: [], ignoreRules: [], failOn: 'high' };
  await fs.writeFile(file, JSON.stringify(template, null, 2) + '\n', 'utf8');
  return { file, created: true };
}
