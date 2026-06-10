import type { Severity } from '../types/finding.js';

export interface Messages {
  reportTitle: string;
  target: string;
  scannedFiles: string;
  noScannedFiles: string;
  riskScore: string;
  grade: string;
  findingsLabel: string;
  noFindings: string;
  file: string;
  evidence: string;
  recommendation: string;
  severityName: Record<Severity, string>;
  summaryCounts: (counts: Record<Severity, number>) => string;
  summaryClean: string;
  parseErrorLabel: string;
}

export const en: Messages = {
  reportTitle: 'Aster Guard MCP Security Report',
  target: 'Target',
  scannedFiles: 'Scanned files',
  noScannedFiles: 'No supported configuration files were found.',
  riskScore: 'Risk Score',
  grade: 'Grade',
  findingsLabel: 'Findings',
  noFindings: 'No security issues were found. This configuration looks safe to use.',
  file: 'File',
  evidence: 'Evidence',
  recommendation: 'Recommendation',
  severityName: {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  },
  summaryCounts: (counts) => {
    const parts: string[] = [];
    for (const sev of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      if (counts[sev] > 0) parts.push(`${counts[sev]} ${sev}`);
    }
    return parts.length > 0 ? parts.join(', ') : 'no issues';
  },
  summaryClean: 'No security issues detected.',
  parseErrorLabel: 'Could not parse file',
};
