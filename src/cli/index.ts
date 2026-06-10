#!/usr/bin/env node
import { Command } from 'commander';
import { registerScanCommand } from './commands/scan.js';
import { registerExplainCommand } from './commands/explain.js';
import { registerHardenCommand } from './commands/harden.js';
import { registerMcpCommand } from './commands/mcp.js';

const program = new Command();

program
  .name('aster-guard')
  .description(
    'A lightweight MCP security guard for Claude Code users and indie AI builders.\n' +
      'Claude Codeユーザーのための、接続前MCPセキュリティ診断ツール。',
  )
  .version('0.1.0');

registerScanCommand(program);
registerExplainCommand(program);
registerHardenCommand(program);
registerMcpCommand(program);

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
