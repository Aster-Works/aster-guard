import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadTargets } from '../src/core/scanner.js';
import { runRules } from '../src/core/rule-engine.js';
import { applyHardenPlan, buildHardenPlan, renderHardenPreview } from '../src/core/harden.js';

const RAW_TOKEN = 'ghp_AbCd1234EfGh5678IjKl9012MnOp3456QrSt';
let dir: string;
let configPath: string;

beforeAll(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aster-guard-harden-'));
  configPath = path.join(dir, '.mcp.json');
  const fixture = path.join(__dirname, 'fixtures', 'critical', '.mcp.json');
  await fs.copyFile(fixture, configPath);
});

afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

describe('harden', () => {
  it('plans secret moves and applies them with a backup', async () => {
    const { targets } = await loadTargets({ file: configPath });
    const findings = runRules(targets);
    const plan = buildHardenPlan(targets, findings);

    expect(plan.moves).toHaveLength(1);
    expect(plan.moves[0]?.envVarName).toBe('GITHUB_TOKEN');
    expect(plan.moves[0]?.redactedValue).not.toContain('AbCd1234');
    expect(plan.advice.length).toBeGreaterThan(0);

    const preview = renderHardenPreview(plan, 'ja');
    expect(preview).toContain('GITHUB_TOKEN');
    expect(preview).not.toContain(RAW_TOKEN);

    const results = await applyHardenPlan(plan);
    expect(results).toHaveLength(1);

    const updated = await fs.readFile(configPath, 'utf8');
    expect(updated).toContain('${GITHUB_TOKEN}');
    expect(updated).not.toContain(RAW_TOKEN);

    const backup = await fs.readFile(results[0]!.backupPath, 'utf8');
    expect(backup).toContain(RAW_TOKEN); // backup preserves the original
  });
});
