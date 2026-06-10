export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  file?: string;
  path?: string;
  evidence?: string;
  redactedEvidence?: string;
  explanationJa: string;
  explanationEn: string;
  recommendationJa: string;
  recommendationEn: string;
}

/** Highest severity first. */
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function isBlocking(severity: Severity): boolean {
  return severity === 'high' || severity === 'critical';
}
