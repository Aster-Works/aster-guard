import type { Command } from 'commander';

export function registerMcpCommand(program: Command): void {
  program
    .command('mcp')
    .description('Start Aster Guard as a local stdio MCP server (read-only tools)')
    .action(async () => {
      const { startMcpServer } = await import('../../mcp/server.js');
      await startMcpServer();
    });
}
