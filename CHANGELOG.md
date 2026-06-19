# Changelog

## Unreleased

## 0.3.2 (2026-06-19)

- Use an absolute GitHub-hosted demo image URL so the README image renders on npmjs.com.
- Update the GitHub Action example to `Aster-Works/aster-guard@v0.3.2`.

## 0.3.1 (2026-06-19)

- Add a README demo image showing sample scan output from a risky `.mcp.json`.
- Update GitHub Action usage examples and package metadata for the `Aster-Works/aster-guard`
  organization repository.
- Terminal and Markdown reports now include optional links to star the project, report issues,
  share on X, or send GitHub Issue Form feedback. JSON/SARIF outputs remain unchanged.
- Terminal and Markdown reports are now bilingual: each finding shows its explanation and
  recommendation in the primary (locale) language followed by the other language. Labels,
  score, and structure stay in the locale language. JSON/SARIF are unchanged (already bilingual).

## 0.3.0 (2026-06-11)

- Team policy file `.aster-guard/policy.json` (`aster-guard policy init`):
  - `allowedRemoteHosts` — hosts AG-007 should trust (supports `*.domain` wildcards)
  - `ignoreRules` — suppress findings of specific rules
  - `failOn` — team-wide default for the scan exit-code threshold (CLI `--fail-on` overrides)
- Invalid policy files are reported as a low finding instead of breaking the scan

## 0.2.0 (2026-06-11)

- `check-install --allow-network`: opt-in npm/GitHub **metadata** checks — package existence
  (hallucinated/slopsquatted names), install-time scripts (preinstall/postinstall), package age,
  weekly downloads, deprecation, archived/stale repos, star count. JSON over HTTPS only;
  code is never downloaded or executed. The `safe_install_plan` MCP tool honors `allowNetwork` too.
- `scan --fail-on <severity>`: configurable exit-code threshold (critical|high|medium|low|info|never)
- `scan <directory>`: a directory argument now runs config discovery inside it
- Composite GitHub Action (`uses: Aster-Works/aster-guard@main`) with `path` / `fail-on` / `sarif` inputs
- CI workflow (lint, typecheck, tests, demo self-scan)
- `examples/demo-risky.mcp.json` demo fixture

## 0.1.1 (2026-06-11)

- Add repository / homepage / bugs metadata for the npm page (no code changes)

## 0.1.0 (2026-06-11)

First public release.

- 12 detection rules (AG-001…AG-012), risk score (0–100) and A–F grade
- Terminal / JSON / Markdown / SARIF 2.1.0 reports, Japanese & English explanations
- `scan` (`--json`, `--report`, `--sarif`, `--compare-baseline`, `--no-home`), `explain`,
  `harden` (`--write` with timestamped backups, atomic writes), `baseline create`,
  `check-install`, `mcp`
- Local stdio MCP server with 6 read-only tools
- Config discovery: Claude Code, Cursor, VS Code (`servers` key), Windsurf, Cline (macOS), Gemini CLI, `.env*`
- Security design: local-first, read-only by default, no telemetry, no external API calls,
  never executes scanned commands, secrets always redacted
