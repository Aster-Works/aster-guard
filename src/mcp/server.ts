import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { ScanReport } from '../types/report.js';
import { VERSION } from '../version.js';
import { registerScanWorkspace } from './tools/scan-workspace.js';
import { registerScanMcpConfig } from './tools/scan-mcp-config.js';
import { registerExplainFinding } from './tools/explain-finding.js';
import { registerHardenConfig } from './tools/harden-config.js';
import { registerSafeInstallPlan } from './tools/safe-install-plan.js';
import { registerGenerateReport } from './tools/generate-report.js';

/** Shared in-process state: the most recent scan, used by generate_report. */
export interface McpState {
  lastReport: ScanReport | null;
}

/**
 * Start the local stdio MCP server. All tools are read-only in v0.1: they
 * never modify files, never execute scanned commands, and never call out to
 * the network.
 */
export async function startMcpServer(): Promise<void> {
  const server = new McpServer({ name: 'aster-guard', version: VERSION });
  const state: McpState = { lastReport: null };

  registerScanWorkspace(server, state);
  registerScanMcpConfig(server, state);
  registerExplainFinding(server);
  registerHardenConfig(server);
  registerSafeInstallPlan(server);
  registerGenerateReport(server, state);

  await server.connect(new StdioServerTransport());
}
