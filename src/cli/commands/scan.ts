import fs from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { hasBlockingFindings, scan } from '../../core/scanner.js';
import { loadPolicy } from '../../core/policy.js';
import { renderJson, renderMarkdown, renderSarif, renderTerminal } from '../../core/report.js';
import { detectLocale } from '../../i18n/index.js';

interface ScanCliOptions {
  json?: boolean;
  report?: string;
  home?: boolean;
  compareBaseline?: boolean;
  sarif?: string;
  failOn?: string;
}

const FAIL_ON_VALUES = ['critical', 'high', 'medium', 'low', 'info', 'never'] as const;

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .argument('[file]', 'a config file to scan, or a directory to run discovery in')
    .description('Scan MCP / Claude Code configuration files for security issues')
    .option('--json', 'print the full report as JSON')
    .option('--report <path>', 'also write a Markdown report to this file')
    .option('--no-home', 'skip configuration files in your home directory')
    .option('--compare-baseline', 'compare against .aster-guard/baseline.json (AG-012 rug pull)')
    .option('--sarif <path>', 'also write a SARIF 2.1.0 report to this file')
    .option(
      '--fail-on <severity>',
      `exit 1 at or above this severity (${FAIL_ON_VALUES.join('|')}); ` +
        'default comes from .aster-guard/policy.json failOn, else "high"',
    )
    .action(async (file: string | undefined, opts: ScanCliOptions) => {
      const locale = detectLocale();
      const explicit = opts.failOn?.toLowerCase() as (typeof FAIL_ON_VALUES)[number] | undefined;
      if (explicit !== undefined && !FAIL_ON_VALUES.includes(explicit)) {
        console.error(`--fail-on must be one of: ${FAIL_ON_VALUES.join(', ')}`);
        process.exitCode = 2;
        return;
      }
      const { policy } = await loadPolicy(process.cwd());
      const failOn = explicit ?? policy.failOn ?? 'high';
      const report = await scan({
        file,
        includeHome: opts.home !== false,
        compareBaseline: opts.compareBaseline === true,
      });

      if (opts.json) {
        console.log(renderJson(report));
      } else {
        console.log(renderTerminal(report, locale));
      }

      if (opts.report) {
        const out = path.resolve(opts.report);
        await fs.writeFile(out, renderMarkdown(report, locale), 'utf8');
        if (!opts.json) {
          console.log(
            locale === 'ja'
              ? `Markdownレポートを書き出しました: ${out}`
              : `Markdown report written to ${out}`,
          );
        }
      }

      if (opts.sarif) {
        const out = path.resolve(opts.sarif);
        await fs.writeFile(out, renderSarif(report), 'utf8');
        if (!opts.json) {
          console.log(
            locale === 'ja'
              ? `SARIFレポートを書き出しました: ${out}`
              : `SARIF report written to ${out}`,
          );
        }
      }

      if (failOn !== 'never' && hasBlockingFindings(report, failOn)) {
        process.exitCode = 1;
      }
    });
}
