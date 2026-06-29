import type { Rule } from './rule.js';
import { AG001 } from './AG001-hidden-agent-instructions.js';
import { AG002 } from './AG002-sensitive-file-exfiltration.js';
import { AG003 } from './AG003-shell-execution.js';
import { AG004 } from './AG004-dangerous-install.js';
import { AG005 } from './AG005-hardcoded-secret.js';
import { AG006 } from './AG006-overbroad-filesystem.js';
import { AG007 } from './AG007-unknown-remote.js';
import { AG008 } from './AG008-tool-shadowing.js';
import { AG009 } from './AG009-obfuscation.js';
import { AG010 } from './AG010-destructive-command.js';
import { AG011 } from './AG011-credential-transmission.js';
import { AG012 } from './AG012-rug-pull.js';
import { AG013 } from './AG013-runtime-env-injection.js';
import { AG014 } from './AG014-package-typosquatting.js';
import { AG015 } from './AG015-privilege-escalation.js';

export const allRules: readonly Rule[] = [
  AG001,
  AG002,
  AG003,
  AG004,
  AG005,
  AG006,
  AG007,
  AG008,
  AG009,
  AG010,
  AG011,
  AG012,
  AG013,
  AG014,
  AG015,
];

/** Look up a rule by id, tolerating formats like "ag003", "AG-003", "AG003". */
export function getRule(id: string): Rule | undefined {
  const normalized = id
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
  return allRules.find((r) => r.id.replace(/[^A-Z0-9]/g, '') === normalized);
}

/** Normalize "ag007" / "AG-007" / "AG007" to a comparable form. */
export function normalizeRuleId(id: string): string {
  return id
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}

export type { Rule, RuleContext, RuleMeta } from './rule.js';
