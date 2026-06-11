import type { Finding, Severity } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';
import type { AsterGuardPolicy } from '../core/policy.js';

export interface RuleContext {
  policy?: AsterGuardPolicy;
}

export interface RuleMeta {
  id: string;
  nameEn: string;
  nameJa: string;
  severity: Severity;
  explanationEn: string;
  explanationJa: string;
  recommendationEn: string;
  recommendationJa: string;
}

export interface Rule extends RuleMeta {
  check(target: ScanTarget, context?: RuleContext): Finding[];
}
