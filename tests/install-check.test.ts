import { describe, expect, it } from 'vitest';
import { analyzeRemote, parseInstallSource, type FetchLike } from '../src/core/install-check.js';

describe('parseInstallSource', () => {
  it('parses explicit prefixes and URLs', () => {
    expect(parseInstallSource('npm:left-pad')).toEqual({ kind: 'npm', name: 'left-pad' });
    expect(parseInstallSource('npm:@scope/pkg@1.2.3')).toEqual({ kind: 'npm', name: '@scope/pkg' });
    expect(parseInstallSource('github:owner/repo')).toEqual({ kind: 'github', repo: 'owner/repo' });
    expect(parseInstallSource('https://github.com/owner/repo.git')).toEqual({
      kind: 'github',
      repo: 'owner/repo',
    });
  });

  it('extracts package names from install commands', () => {
    expect(parseInstallSource('npx -y @scope/pkg@1.2.3')).toEqual({
      kind: 'npm',
      name: '@scope/pkg',
    });
    expect(parseInstallSource('npm install -g some-package')).toEqual({
      kind: 'npm',
      name: 'some-package',
    });
    expect(parseInstallSource('claude mcp add notes -- npx -y notes-mcp')).toEqual({
      kind: 'npm',
      name: 'notes-mcp',
    });
  });

  it('handles bare names and garbage', () => {
    expect(parseInstallSource('lodash')).toEqual({ kind: 'npm', name: 'lodash' });
    expect(parseInstallSource('!!! ???')).toEqual({ kind: 'unknown' });
    expect(parseInstallSource('https://example.com/foo')).toEqual({ kind: 'unknown' });
  });
});

function mockFetch(routes: Record<string, { status: number; body: unknown }>): FetchLike {
  return (url) => {
    const route = Object.entries(routes).find(([prefix]) => url.startsWith(prefix));
    const res = route ? route[1] : { status: 404, body: {} };
    return Promise.resolve({
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      json: () => Promise.resolve(res.body),
    });
  };
}

const NOW = Date.parse('2026-06-11T00:00:00Z');

describe('analyzeRemote (mocked network)', () => {
  it('flags packages that do not exist on npm', async () => {
    const signals = await analyzeRemote('npm:ghost-package', mockFetch({}), NOW);
    expect(signals).toHaveLength(1);
    expect(signals[0]?.level).toBe('high');
    expect(signals[0]?.en).toContain('does not exist');
  });

  it('flags install-time scripts and very new packages', async () => {
    const signals = await analyzeRemote(
      'npm:shiny-mcp',
      mockFetch({
        'https://registry.npmjs.org/shiny-mcp': {
          status: 200,
          body: {
            'dist-tags': { latest: '1.0.0' },
            versions: {
              '1.0.0': { scripts: { postinstall: 'node setup.js' }, repository: { url: 'x' } },
            },
            time: { created: '2026-06-01T00:00:00Z' },
          },
        },
        'https://api.npmjs.org/downloads/point/last-week/shiny-mcp': {
          status: 200,
          body: { downloads: 12 },
        },
      }),
      NOW,
    );
    const levels = signals.map((s) => s.level);
    expect(signals.some((s) => s.en.includes('postinstall'))).toBe(true);
    expect(levels).toContain('high'); // install script
    expect(signals.some((s) => s.en.includes('30 days'))).toBe(true);
    expect(signals.some((s) => s.en.includes('12 downloads'))).toBe(true);
  });

  it('stays quiet for a healthy package', async () => {
    const signals = await analyzeRemote(
      'npm:solid-mcp',
      mockFetch({
        'https://registry.npmjs.org/solid-mcp': {
          status: 200,
          body: {
            'dist-tags': { latest: '3.4.0' },
            versions: { '3.4.0': { repository: { url: 'x' } } },
            time: { created: '2024-01-01T00:00:00Z' },
          },
        },
        'https://api.npmjs.org/downloads/point/last-week/solid-mcp': {
          status: 200,
          body: { downloads: 54321 },
        },
      }),
      NOW,
    );
    expect(signals).toHaveLength(0);
  });

  it('flags archived and stale GitHub repositories', async () => {
    const signals = await analyzeRemote(
      'github:old/thing',
      mockFetch({
        'https://api.github.com/repos/old/thing': {
          status: 200,
          body: { archived: true, pushed_at: '2024-01-01T00:00:00Z', stargazers_count: 2 },
        },
      }),
      NOW,
    );
    expect(signals.some((s) => s.en.includes('archived'))).toBe(true);
    expect(signals.some((s) => s.en.includes('over a year'))).toBe(true);
    expect(signals.some((s) => s.en.includes('2 stars'))).toBe(true);
  });

  it('degrades gracefully on network errors', async () => {
    const failing: FetchLike = () => Promise.reject(new Error('boom'));
    const signals = await analyzeRemote('npm:whatever', failing, NOW);
    expect(signals).toHaveLength(1);
    expect(signals[0]?.level).toBe('info');
  });
});
