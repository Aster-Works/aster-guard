# Changelog

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
