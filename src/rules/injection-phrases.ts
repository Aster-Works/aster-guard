import type { Confidence } from '../types/finding.js';

/**
 * Phrases that look like hidden instructions aimed at the AI agent
 * (Tool Poisoning / prompt injection). Shared by AG-001 (which matches them
 * directly in config strings) and AG-016 (which re-runs the high-confidence
 * subset after stripping invisible characters, to catch phrases that were
 * hidden from AG-001 by zero-width steganography).
 */
export const INJECTION_PHRASES: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  {
    re: /ignore\s+(?:all\s+|any\s+)?(?:previous\s+|prior\s+|above\s+)?instructions/i,
    confidence: 'high',
  },
  { re: /do\s+not\s+(?:tell|inform|notify|alert)\s+the\s+user/i, confidence: 'high' },
  { re: /without\s+(?:mentioning|telling|informing|notifying)/i, confidence: 'high' },
  { re: /hidden\s+instruction/i, confidence: 'high' },
  { re: /\bsecretly\b/i, confidence: 'medium' },
  { re: /\bsilently\b/i, confidence: 'medium' },
  { re: /system\s+prompt/i, confidence: 'medium' },
  { re: /developer\s+message/i, confidence: 'medium' },
  { re: /before\s+using\s+this\s+tool/i, confidence: 'medium' },
];

/**
 * The high-confidence subset — unambiguous injection imperatives. AG-016 uses
 * only these for its "reveal after de-obfuscation" escalation so that weak
 * signals (e.g. the phrase "system prompt") don't trigger a critical finding.
 */
export const HIGH_CONFIDENCE_INJECTION: ReadonlyArray<RegExp> = INJECTION_PHRASES.filter(
  (p) => p.confidence === 'high',
).map((p) => p.re);
