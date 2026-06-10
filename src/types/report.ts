import type { Finding } from './finding.js';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScanReport {
  target: string;
  scannedFiles: string[];
  riskScore: number;
  grade: Grade;
  findings: Finding[];
  summaryJa: string;
  summaryEn: string;
}
