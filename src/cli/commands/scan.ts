import fs from 'node:fs/promises';
import path from 'node:path';
import type { Command } from 'commander';
import { hasBlockingFindings, scan } from '../../core/scanner.js';
import { renderJson, renderMarkdown, renderTerminal } from '../../core/report.js';
import { detectLocale } from '../../i18n/index.js';

interface ScanCliOptions {
  json?: boolean;
  report?: string;
  home?: boolean;
}

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .argument('[file]', 'scan a single configuration file instead of auto-discovery')
    .description('Scan MCP / Claude Code configuration files for security issues')
    .option('--json', 'print the full report as JSON')
    .option('--report <path>', 'also write a Markdown report to this file')
    .option('--no-home', 'skip configuration files in your home directory')
    .action(async (file: string | undefined, opts: ScanCliOptions) => {
      const locale = detectLocale();
      const report = await scan({ file, includeHome: opts.home !== false });

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

      if (hasBlockingFindings(report)) {
        process.exitCode = 1;
      }
    });
}
