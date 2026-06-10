import { describe, expect, it } from 'vitest';
import {
  ParseError,
  extractServers,
  parseEnvFile,
  parseJsonWithLocation,
} from '../src/core/parser.js';

describe('parseJsonWithLocation', () => {
  it('parses valid JSON', () => {
    expect(parseJsonWithLocation('{"a":1}', 'x.json')).toEqual({ a: 1 });
  });

  it('throws a ParseError naming the file', () => {
    try {
      parseJsonWithLocation('{"a":\n  oops}', 'broken.json');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ParseError);
      expect((err as ParseError).message).toContain('broken.json');
      expect((err as ParseError).message).toContain('Invalid JSON');
    }
  });
});

describe('extractServers', () => {
  it('normalizes a standard .mcp.json entry', () => {
    const json = {
      mcpServers: {
        files: {
          command: 'npx',
          args: ['-y', 'pkg'],
          env: { K: 'v' },
          type: 'stdio',
        },
      },
    };
    const servers = extractServers(json, '/x/.mcp.json');
    expect(servers).toHaveLength(1);
    expect(servers[0]).toMatchObject({
      name: 'files',
      command: 'npx',
      args: ['-y', 'pkg'],
      env: { K: 'v' },
      type: 'stdio',
      jsonPath: 'mcpServers.files',
    });
  });

  it('finds nested mcpServers blocks like ~/.claude.json projects', () => {
    const json = {
      mcpServers: { top: { command: 'x' } },
      projects: {
        '/some/project': { mcpServers: { sub: { url: 'https://example.com/mcp' } } },
      },
    };
    const servers = extractServers(json, '/home/.claude.json');
    expect(servers.map((s) => s.name).sort()).toEqual(['sub', 'top']);
    const sub = servers.find((s) => s.name === 'sub');
    expect(sub?.type).toBe('http');
    expect(sub?.jsonPath).toBe('projects./some/project.mcpServers.sub');
  });

  it('accepts the VS Code "servers" key when entries look like servers', () => {
    const servers = extractServers(
      { servers: { docs: { command: 'npx', args: ['-y', 'pkg'] } } },
      '/x/.vscode/mcp.json',
    );
    expect(servers).toHaveLength(1);
    expect(servers[0]?.jsonPath).toBe('servers.docs');
  });

  it('ignores a "servers" key whose values are not server definitions', () => {
    expect(extractServers({ servers: { a: 'production', b: 'staging' } }, 'f')).toHaveLength(0);
  });

  it('infers type and tolerates malformed entries', () => {
    const servers = extractServers({ mcpServers: { weird: 'not-an-object' } }, 'f');
    expect(servers).toHaveLength(1);
    expect(servers[0]?.type).toBe('unknown');
    expect(servers[0]?.args).toEqual([]);
  });
});

describe('parseEnvFile', () => {
  it('parses keys, values, comments, export, and quotes', () => {
    const vars = parseEnvFile(
      ['# comment', '', 'FOO=bar', 'export QUOTED="hello world"', "SINGLE='x'", 'BAD LINE'].join(
        '\n',
      ),
    );
    expect(vars).toEqual([
      { key: 'FOO', value: 'bar', line: 3 },
      { key: 'QUOTED', value: 'hello world', line: 4 },
      { key: 'SINGLE', value: 'x', line: 5 },
    ]);
  });
});
