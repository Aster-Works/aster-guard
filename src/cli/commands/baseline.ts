import type { Command } from 'commander';
import { loadTargets } from '../../core/scanner.js';
import { createBaseline } from '../../core/baseline.js';
import { detectLocale } from '../../i18n/index.js';

interface BaselineCliOptions {
  home?: boolean;
}

export function registerBaselineCommand(program: Command): void {
  program
    .command('baseline')
    .argument('<action>', 'currently only "create"')
    .description('Snapshot current MCP servers for rug-pull detection (scan --compare-baseline)')
    .option('--no-home', 'skip configuration files in your home directory')
    .action(async (action: string, opts: BaselineCliOptions) => {
      const ja = detectLocale() === 'ja';
      if (action !== 'create') {
        console.error(
          ja
            ? `不明なアクション「${action}」です。使い方: aster-guard baseline create`
            : `Unknown action "${action}". Usage: aster-guard baseline create`,
        );
        process.exitCode = 1;
        return;
      }
      const { targets } = await loadTargets({ includeHome: opts.home !== false });
      const result = await createBaseline(targets, process.cwd());
      console.log(
        ja
          ? `ベースラインを保存しました: ${result.file}（サーバー ${result.count}件）`
          : `Baseline written to ${result.file} (${result.count} servers)`,
      );
    });
}
