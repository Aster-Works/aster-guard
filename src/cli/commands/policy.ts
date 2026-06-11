import type { Command } from 'commander';
import { initPolicy } from '../../core/policy.js';
import { detectLocale } from '../../i18n/index.js';

export function registerPolicyCommand(program: Command): void {
  program
    .command('policy')
    .argument('<action>', 'currently only "init"')
    .description('Manage the team policy file (.aster-guard/policy.json)')
    .action(async (action: string) => {
      const ja = detectLocale() === 'ja';
      if (action !== 'init') {
        console.error(
          ja
            ? `不明なアクション「${action}」です。使い方: aster-guard policy init`
            : `Unknown action "${action}". Usage: aster-guard policy init`,
        );
        process.exitCode = 1;
        return;
      }
      const result = await initPolicy(process.cwd());
      console.log(
        result.created
          ? ja
            ? `ポリシーファイルを作成しました: ${result.file}`
            : `Policy file created: ${result.file}`
          : ja
            ? `すでに存在するため上書きしませんでした: ${result.file}`
            : `Already exists; not overwritten: ${result.file}`,
      );
    });
}
