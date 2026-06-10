import type { Confidence } from '../types/finding.js';
import type { Rule } from './rule.js';
import { makeFinding, scanUnits } from './helpers.js';

const PATTERNS: ReadonlyArray<{ re: RegExp; confidence: Confidence }> = [
  { re: /webhook\.site/i, confidence: 'high' },
  { re: /requestbin|hookbin|pipedream\.net/i, confidence: 'high' },
  { re: /pastebin\.com/i, confidence: 'high' },
  { re: /discord(?:app)?\.com\/api\/webhooks/i, confidence: 'high' },
  { re: /\bexfiltrat/i, confidence: 'high' },
  {
    re: /\bsend\s+(?:the\s+|your\s+)?(?:token|key|credential|password)s?\b/i,
    confidence: 'medium',
  },
  {
    re: /\bupload\s+(?:the\s+|your\s+)?(?:token|key|credential|password)s?\b/i,
    confidence: 'medium',
  },
  { re: /\bpost\s+(?:the\s+|your\s+)?credentials?\b/i, confidence: 'medium' },
];

export const AG011: Rule = {
  id: 'AG-011',
  nameEn: 'Credential Transmission Risk',
  nameJa: '認証情報の外部送信リスク',
  severity: 'critical',
  explanationEn:
    'The configuration references services or phrases associated with sending data out (e.g. webhook.site, "send token"). This is a strong signal that credentials could be transmitted to a third party.',
  explanationJa:
    'データの外部送信に使われるサービスや表現（例：webhook.site、「send token」）への言及があります。認証情報が第三者へ送信される強いシグナルです。',
  recommendationEn:
    'Do not connect this server. Identify why the endpoint or phrase is present; if you already connected it, rotate any credentials it could have seen.',
  recommendationJa:
    'このサーバーには接続しないでください。なぜこの送信先や表現が含まれているのかを確認し、すでに接続したことがある場合は、見られた可能性のある認証情報をすべて再発行してください。',
  check(target) {
    const findings = [];
    for (const unit of scanUnits(target)) {
      const hit = PATTERNS.find((p) => p.re.test(unit.value));
      if (hit) {
        findings.push(
          makeFinding(AG011, {
            target,
            confidence: hit.confidence,
            path: unit.path,
            evidence: unit.value,
          }),
        );
      }
    }
    return findings;
  },
};
