import type { Command } from 'commander';
import pc from 'picocolors';
import { allRules, getRule } from '../../rules/index.js';
import { detectLocale, getMessages } from '../../i18n/index.js';

export function registerExplainCommand(program: Command): void {
  program
    .command('explain')
    .argument('<ruleId>', 'rule id, e.g. AG-003')
    .description('Explain an Aster Guard rule in plain language')
    .action((ruleId: string) => {
      const locale = detectLocale();
      const m = getMessages(locale);
      const rule = getRule(ruleId);
      if (!rule) {
        const known = allRules.map((r) => r.id).join(', ');
        console.error(
          locale === 'ja'
            ? `ルール「${ruleId}」は見つかりませんでした。利用可能なルール: ${known}`
            : `Unknown rule "${ruleId}". Available rules: ${known}`,
        );
        process.exitCode = 1;
        return;
      }
      const ja = locale === 'ja';
      console.log(pc.bold(`${rule.id} — ${ja ? rule.nameJa : rule.nameEn}`));
      console.log(`${locale === 'ja' ? '深刻度' : 'Severity'}: ${m.severityName[rule.severity]}`);
      console.log('');
      console.log(ja ? rule.explanationJa : rule.explanationEn);
      console.log('');
      console.log(`${m.recommendation}: ${ja ? rule.recommendationJa : rule.recommendationEn}`);
    });
}
