import type { Finding, Severity } from '../types/finding.js';
import type { ScanTarget } from '../types/config.js';

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
  check(target: ScanTarget): Finding[];
}
