---
title: 'I published my first GitHub Marketplace Action: Aster Guard MCP'
published: false
description: 'A lightweight, local-first security check for MCP and Claude Code configuration files.'
tags: mcp, security, githubactions, claude
---

I just published my first GitHub Marketplace Action: **Aster Guard MCP**.

Marketplace:
https://github.com/marketplace/actions/aster-guard-mcp

Repository:
https://github.com/Aster-Works/aster-guard

It is a lightweight, local-first security scanner for MCP and Claude Code configuration files.

The goal is intentionally small:

> Before connecting an MCP server to your AI coding environment, check whether the configuration looks safe enough to trust.

## Why I built it

MCP is becoming a very practical way to connect AI coding tools to real developer systems.

Depending on the MCP server, an AI agent may gain access to:

- local files
- shell commands
- browsers
- databases
- SaaS APIs
- internal developer tools

That is powerful. It is also a meaningful security boundary.

For example, a single `.mcp.json` entry can define a command to run, expose environment variables, grant filesystem access, or connect to a remote endpoint. Tool descriptions can also contain hidden instructions that shape how an agent behaves.

So I wanted a small check that runs before that connection happens.

## What Aster Guard MCP does

Aster Guard statically scans MCP and Claude Code configuration files.

The important part is what it does **not** do:

- it does not start the MCP servers it scans
- it does not execute scanned commands
- it does not send telemetry
- it does not call external APIs during normal scans
- it redacts secrets in output

It looks for risk patterns such as:

- hidden agent instructions in tool descriptions
- hardcoded secrets
- sensitive file paths such as `.ssh`, cloud credentials, and `.env`
- shell execution and dangerous install commands
- destructive commands
- overbroad filesystem access
- unknown remote MCP endpoints
- tool-name shadowing
- obfuscated command patterns

The output includes a risk score, a grade, findings, and recommended next steps in English and Japanese.

## Try it locally

You can run it without installing anything globally:

```bash
npx -y @asterworks/aster-guard scan
```

Or scan a specific config file:

```bash
npx -y @asterworks/aster-guard scan .mcp.json
```

## Use it in GitHub Actions

Now that it is on GitHub Marketplace, you can add it to a workflow:

```yaml
- uses: Aster-Works/aster-guard@v0.3.2
  with:
    path: .
    fail-on: high
```

You can also produce SARIF and upload the result to GitHub code scanning:

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

## Where it fits

Aster Guard is not trying to be a full security platform.

It is not a runtime firewall, antivirus tool, SIEM, or complete supply-chain scanner. It is a narrow pre-connection check for MCP configuration risk.

That narrow scope is deliberate. I wanted something that individual developers and small teams can run quickly before trusting an unfamiliar MCP server.

## What I would love feedback on

This is still early, so the most useful feedback is practical:

- Are the findings easy to understand?
- Does the report help you decide what to do next?
- Are there common MCP configuration risks it should detect?
- Would this be useful in CI, or mainly as a local pre-check?

If you are experimenting with MCP or Claude Code, I would love for you to try it on a real configuration and open an issue with anything confusing, noisy, or missing.

Links:

- GitHub Marketplace: https://github.com/marketplace/actions/aster-guard-mcp
- GitHub repository: https://github.com/Aster-Works/aster-guard
- npm: https://www.npmjs.com/package/@asterworks/aster-guard
