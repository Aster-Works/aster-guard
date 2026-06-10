import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { allRules, getRule } from '../../rules/index.js';

export function registerExplainFinding(server: McpServer): void {
  server.registerTool(
    'explain_finding',
    {
      title: 'Explain an Aster Guard rule',
      description:
        'Explain one Aster Guard rule (AG-001 … AG-011) in plain language, in Japanese or English.',
      inputSchema: {
        ruleId: z.string().describe('Rule id, e.g. "AG-003"'),
        language: z.enum(['ja', 'en']).default('ja'),
      },
      annotations: { readOnlyHint: true },
    },
    ({ ruleId, language }) => {
      const rule = getRule(ruleId);
      if (!rule) {
        const known = allRules.map((r) => r.id).join(', ');
        return {
          content: [{ type: 'text', text: `Unknown rule "${ruleId}". Available rules: ${known}` }],
          isError: true,
        };
      }
      const ja = language === 'ja';
      const text = [
        `${rule.id} — ${ja ? rule.nameJa : rule.nameEn}`,
        `${ja ? '深刻度' : 'Severity'}: ${rule.severity}`,
        '',
        ja ? rule.explanationJa : rule.explanationEn,
        '',
        `${ja ? '対策' : 'Recommendation'}: ${ja ? rule.recommendationJa : rule.recommendationEn}`,
      ].join('\n');
      return { content: [{ type: 'text', text }] };
    },
  );
}
