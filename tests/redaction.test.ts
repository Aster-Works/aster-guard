import { describe, expect, it } from 'vitest';
import {
  isSecretKeyName,
  looksLikeSecretValue,
  matchSecretValue,
  redactSecret,
  redactText,
} from '../src/core/redaction.js';

describe('redactSecret', () => {
  it('keeps a recognizable prefix and the last 4 characters', () => {
    const out = redactSecret('sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456');
    expect(out.startsWith('sk-ant-')).toBe(true);
    expect(out.endsWith('3456')).toBe(true);
    expect(out).toContain('****');
    expect(out).not.toContain('abcdefghijklmnopqrstuvwxyz');
  });

  it('fully masks short values', () => {
    expect(redactSecret('abc')).toBe('****');
    expect(redactSecret('12345678')).not.toContain('1');
  });

  it('never returns the original value', () => {
    for (const v of ['ghp_AbCd1234EfGh5678IjKl9012MnOp3456QrSt', 'hunter2hunter2', 'p@ss']) {
      expect(redactSecret(v)).not.toBe(v);
    }
  });
});

describe('redactText', () => {
  it('scrubs known token formats inside free text', () => {
    const text = 'header is Bearer abcdefghijklmnop1234 ok';
    const out = redactText(text);
    expect(out).not.toContain('abcdefghijklmnop1234');
    expect(out).toContain('Bearer ');
  });

  it('leaves normal text alone', () => {
    expect(redactText('npx -y @modelcontextprotocol/server-filesystem ./src')).toBe(
      'npx -y @modelcontextprotocol/server-filesystem ./src',
    );
  });
});

describe('secret detection helpers', () => {
  it('matches known token formats', () => {
    expect(matchSecretValue('ghp_AbCd1234EfGh5678IjKl9012MnOp3456QrSt')?.label).toBe(
      'GitHub token',
    );
    expect(matchSecretValue('hello world')).toBeUndefined();
  });

  it('recognizes secret-ish key names', () => {
    expect(isSecretKeyName('GITHUB_TOKEN')).toBe(true);
    expect(isSecretKeyName('apiKey')).toBe(true);
    expect(isSecretKeyName('AUTHOR')).toBe(false);
    expect(isSecretKeyName('LOG_LEVEL')).toBe(false);
  });

  it('ignores placeholders and env references', () => {
    expect(looksLikeSecretValue('${GITHUB_TOKEN}')).toBe(false);
    expect(looksLikeSecretValue('changeme')).toBe(false);
    expect(looksLikeSecretValue('<your-token>')).toBe(false);
    expect(looksLikeSecretValue('Abc123Xyz456')).toBe(true);
  });
});
