#!/usr/bin/env node
import { Command } from 'commander';
import { VERSION } from '../version.js';
import { registerScanCommand } from './commands/scan.js';
import { registerExplainCommand } from './commands/explain.js';
import { registerHardenCommand } from './commands/harden.js';
import { registerMcpCommand } from './commands/mcp.js';
import { registerBaselineCommand } from './commands/baseline.js';
import { registerCheckInstallCommand } from './commands/check-install.js';

const program = new Command();

program
  .name('aster-guard')
  .description(
    'A lightweight MCP security guard for Claude Code users and indie AI builders.\n' +
      'Claude Codeユーザーのための、接続前MCPセキュリティ診断ツール。',
  )
  .version(VERSION);

registerScanCommand(program);
registerExplainCommand(program);
registerHardenCommand(program);
registerMcpCommand(program);
registerBaselineCommand(program);
registerCheckInstallCommand(program);

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
