import type { Confidence, Finding, Severity } from '../types/finding.js';
import type { Grade } from '../types/report.js';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 35,
  high: 25,
  medium: 12,
  low: 5,
  info: 0,
};

const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  high: 1.0,
  medium: 0.75,
  low: 0.5,
};

/** Start from 100, subtract weighted deductions, clamp to 0–100. */
export function computeRiskScore(findings: readonly Finding[]): number {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_WEIGHT[f.severity] * CONFIDENCE_MULTIPLIER[f.confidence];
  }
  return Math.min(100, Math.max(0, Math.round(score)));
}

export function gradeForScore(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
