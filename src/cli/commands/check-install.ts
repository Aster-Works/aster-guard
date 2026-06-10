import type { Command } from 'commander';
import { analyzeInstallSource, INSTALL_CHECKLIST } from '../../core/install-check.js';
import { detectLocale } from '../../i18n/index.js';
import { isBlocking } from '../../types/finding.js';

export function registerCheckInstallCommand(program: Command): void {
  program
    .command('check-install')
    .argument('<source>', 'install command, npm package, or repository URL')
    .description('Statically analyze an MCP install command before running it (no network access)')
    .action((source: string) => {
      const ja = detectLocale() === 'ja';
      const findings = analyzeInstallSource(source);
      if (findings.length === 0) {
        console.log(
          ja
            ? '既知の危険なパターンは見つかりませんでした（静的検査のみ。安全の証明ではありません）。'
            : 'No known risky patterns found (static check only — not a proof of safety).',
        );
      } else {
        console.log(
          ja ? `リスクシグナル ${findings.length}件:` : `${findings.length} risk signal(s):`,
        );
        for (const f of findings) {
          console.log(`- [${f.severity}] ${f.ruleId} ${f.title}`);
          console.log(`  ${ja ? f.explanationJa : f.explanationEn}`);
        }
      }
      console.log('');
      console.log(INSTALL_CHECKLIST);
      if (findings.some((f) => isBlocking(f.severity))) {
        process.exitCode = 1;
      }
    });
}
