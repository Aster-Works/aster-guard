import { describe, expect, it } from 'vitest';
import { computeRiskScore, gradeForScore } from '../src/core/scoring.js';
import type { Confidence, Finding, Severity } from '../src/types/finding.js';

function finding(severity: Severity, confidence: Confidence): Finding {
  return {
    ruleId: 'AG-999',
    title: 'test',
    severity,
    confidence,
    explanationJa: '',
    explanationEn: '',
    recommendationJa: '',
    recommendationEn: '',
  };
}

describe('computeRiskScore', () => {
  it('returns 100 for no findings', () => {
    expect(computeRiskScore([])).toBe(100);
  });

  it('applies severity weights at high confidence', () => {
    expect(computeRiskScore([finding('critical', 'high')])).toBe(65);
    expect(computeRiskScore([finding('high', 'high')])).toBe(75);
    expect(computeRiskScore([finding('medium', 'high')])).toBe(88);
    expect(computeRiskScore([finding('low', 'high')])).toBe(95);
    expect(computeRiskScore([finding('info', 'high')])).toBe(100);
  });

  it('applies confidence multipliers', () => {
    expect(computeRiskScore([finding('high', 'medium')])).toBe(81); // 100 - 18.75
    expect(computeRiskScore([finding('high', 'low')])).toBe(88); // 100 - 12.5
  });

  it('clamps at 0', () => {
    const findings = Array.from({ length: 5 }, () => finding('critical', 'high'));
    expect(computeRiskScore(findings)).toBe(0);
  });
});

describe('gradeForScore', () => {
  it('maps scores to grades at the documented boundaries', () => {
    expect(gradeForScore(100)).toBe('A');
    expect(gradeForScore(90)).toBe('A');
    expect(gradeForScore(89)).toBe('B');
    expect(gradeForScore(75)).toBe('B');
    expect(gradeForScore(74)).toBe('C');
    expect(gradeForScore(60)).toBe('C');
    expect(gradeForScore(59)).toBe('D');
    expect(gradeForScore(40)).toBe('D');
    expect(gradeForScore(39)).toBe('F');
    expect(gradeForScore(0)).toBe('F');
  });
});
