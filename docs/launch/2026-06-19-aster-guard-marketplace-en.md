---
title: 'Aster Guard MCP is now on GitHub Marketplace'
description: 'A lightweight, local-first security check for MCP and Claude Code configuration files.'
date: '2026-06-19'
tags:
  - mcp
  - security
  - github-actions
  - claude-code
---

# Aster Guard MCP is now on GitHub Marketplace

Aster Guard MCP is now available as a GitHub Marketplace Action:

https://github.com/marketplace/actions/aster-guard-mcp

It is a lightweight, local-first security check for Claude Code users, MCP adopters, and indie AI builders. Its job is intentionally narrow:

> Before you connect an MCP server, check whether the configuration looks safe enough to trust.

## Why this exists

MCP servers are powerful because they let an AI tool reach outside the chat. Depending on the server, that can mean files, shell commands, databases, browsers, SaaS APIs, and local developer tools.

That power is useful, but it also changes the security question. A single `.mcp.json` entry can:

- run a command
- expose an environment variable
- grant broad filesystem access
- connect to a remote endpoint
- contain hidden instructions that shape agent behavior

Aster Guard is meant to be the small check you run before crossing that line.

## What Aster Guard does

Aster Guard statically scans MCP and Claude Code configuration files. It does not start the MCP servers it scans.

It looks for risk patterns such as:

- hidden agent instructions in tool descriptions
- hardcoded secrets
- sensitive file access patterns such as `.ssh`, cloud credentials, and `.env`
- shell execution and dangerous install commands
- destructive commands
- overbroad filesystem access
- unknown remote MCP endpoints
- tool-name shadowing
- obfuscated command patterns

It then produces a risk score, a grade, and readable findings in Japanese and English.

## Try it locally

```bash
npx -y @asterworks/aster-guard scan
```

You can also scan a specific file:

```bash
npx -y @asterworks/aster-guard scan .mcp.json
```

## Use it in GitHub Actions

```yaml
- uses: Aster-Works/aster-guard@v0.3.2
  with:
    path: .
    fail-on: high
```

For SARIF output:

```yaml
- uses: Aster-Works/aster-guard@v0.3.2
  with:
    path: .
    fail-on: high
    sarif: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## Design principles

Aster Guard follows a few simple rules:

- Local-first by default
- No telemetry
- Does not execute scanned commands
- Does not start third-party MCP servers
- Redacts secrets in output
- Only calls external package or GitHub metadata APIs when you explicitly opt in with `--allow-network`

This is not a runtime firewall, antivirus product, SIEM, or full supply-chain platform. It is a focused pre-connection check for MCP configuration risk.

## Links

- GitHub Marketplace: https://github.com/marketplace/actions/aster-guard-mcp
- GitHub repository: https://github.com/Aster-Works/aster-guard
- npm: https://www.npmjs.com/package/@asterworks/aster-guard

If you try it on a real MCP configuration, feedback is very welcome. The most useful feedback is whether the findings are understandable and whether they help you decide what to do next.
