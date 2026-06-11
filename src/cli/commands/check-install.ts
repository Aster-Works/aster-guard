import type { Command } from 'commander';
import {
  analyzeInstallSource,
  analyzeRemote,
  INSTALL_CHECKLIST,
  renderRemoteSignals,
} from '../../core/install-check.js';
import { detectLocale } from '../../i18n/index.js';
import { isBlocking } from '../../types/finding.js';

interface CheckInstallCliOptions {
  allowNetwork?: boolean;
}

export function registerCheckInstallCommand(program: Command): void {
  program
    .command('check-install')
    .argument('<source>', 'install command, npm package, or repository URL')
    .description(
      'Analyze an MCP install command before running it (static by default; ' +
        '--allow-network adds npm/GitHub metadata checks)',
    )
    .option(
      '--allow-network',
      'fetch npm/GitHub metadata over HTTPS (JSON only; code is never downloaded or executed)',
    )
    .action(async (source: string, opts: CheckInstallCliOptions) => {
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
      let remoteHigh = false;
      console.log('');
      if (opts.allowNetwork) {
        const signals = await analyzeRemote(source);
        remoteHigh = signals.some((s) => s.level === 'high');
        console.log(ja ? 'リモート検査（メタデータのみ取得）:' : 'Remote check (metadata only):');
        for (const line of renderRemoteSignals(signals, ja ? 'ja' : 'en')) console.log(line);
        console.log('');
      } else {
        console.log(
          ja
            ? 'ヒント: --allow-network を付けると、npm/GitHubのメタデータ検査（存在確認・installスクリプト・公開日など）も行います。'
            : 'Tip: add --allow-network to also check npm/GitHub metadata (existence, install scripts, age).',
        );
        console.log('');
      }
      console.log(INSTALL_CHECKLIST);
      if (findings.some((f) => isBlocking(f.severity)) || remoteHigh) {
        process.exitCode = 1;
      }
    });
}
