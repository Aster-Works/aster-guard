import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadTargets } from '../../core/scanner.js';
import { runRules } from '../../core/rule-engine.js';
import { buildHardenPlan, renderHardenPreview } from '../../core/harden.js';
import { detectLocale } from '../../i18n/index.js';

export function registerHardenConfig(server: McpServer): void {
  server.registerTool(
    'harden_config',
    {
      title: 'Suggest safer configuration changes',
      description:
        'Generate hardening suggestions for an MCP configuration file (move secrets to env vars, ' +
        'narrow paths, …). Always returns a preview only — the MCP tool never writes files in v0.1. ' +
        'To apply changes, run `aster-guard harden --write` from the CLI.',
      inputSchema: {
        configPath: z.string().describe('Path to the configuration file'),
        write: z
          .boolean()
          .default(false)
          .describe('Ignored in v0.1: the MCP tool is always read-only'),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ configPath, write }) => {
      try {
        const { targets } = await loadTargets({ file: configPath });
        const findings = runRules(targets);
        const plan = buildHardenPlan(targets, findings);
        let text = renderHardenPreview(plan, detectLocale());
        if (write) {
          text +=
            '\nNote: this MCP tool is read-only in v0.1; nothing was written. ' +
            'Apply changes with the CLI: `aster-guard harden --write`.';
        }
        return { content: [{ type: 'text', text }] };
      } catch (err) {
        return {
          content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
          isError: true,
        };
      }
    },
  );
}
