import type { Command } from 'commander';
import { loadTargets } from '../../core/scanner.js';
import { runRules } from '../../core/rule-engine.js';
import { applyHardenPlan, buildHardenPlan, renderHardenPreview } from '../../core/harden.js';
import { detectLocale } from '../../i18n/index.js';

interface HardenCliOptions {
  write?: boolean;
  home?: boolean;
}

export function registerHardenCommand(program: Command): void {
  program
    .command('harden')
    .argument('[file]', 'harden a single configuration file instead of auto-discovery')
    .description('Suggest (and optionally apply) safer configuration changes')
    .option('--write', 'apply safe fixes; a timestamped backup is created for every modified file')
    .option('--no-home', 'skip configuration files in your home directory')
    .action(async (file: string | undefined, opts: HardenCliOptions) => {
      const locale = detectLocale();
      const ja = locale === 'ja';
      const { targets } = await loadTargets({ file, includeHome: opts.home !== false });
      const findings = runRules(targets);
      const plan = buildHardenPlan(targets, findings);

      console.log(renderHardenPreview(plan, locale));

      if (!opts.write) return;
      if (plan.moves.length === 0) {
        console.log(ja ? '書き込みが必要な変更はありません。' : 'Nothing to write.');
        return;
      }
      const results = await applyHardenPlan(plan);
      for (const r of results) {
        console.log(ja ? `更新しました: ${r.file}` : `Updated: ${r.file}`);
        console.log(ja ? `  バックアップ: ${r.backupPath}` : `  Backup: ${r.backupPath}`);
        console.log(
          ja
            ? `  設定が必要な環境変数: ${r.envVarNames.join(', ')}`
            : `  Environment variables to set: ${r.envVarNames.join(', ')}`,
        );
      }
    });
}
