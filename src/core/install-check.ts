import type { ScanTarget } from '../types/config.js';
import type { Finding } from '../types/finding.js';
import { extractServers } from './parser.js';
import { runRules } from './rule-engine.js';

export const INSTALL_CHECKLIST = `Safety checklist before installing an MCP server / MCPサーバー導入前チェックリスト:
1. Verify the author/organization behind the package or repository. / パッケージ・リポジトリの提供元（作者・組織）を確認する。
2. Check repository activity: stars, recent commits, open issues. / スター数・更新履歴・Issueの状況を確認する。
3. Pin an exact version (e.g. package@1.2.3) instead of "latest". / バージョンを固定してインストールする（latestを避ける）。
4. Grant the narrowest possible permissions and paths first. / 最初は最小限の権限・最小限のパスで試す。
5. Re-run "aster-guard scan" after adding it to your config. / 設定に追加したら aster-guard scan を再実行する。`;

/**
 * Statically analyze an install command / package name / repo URL by wrapping
 * it in a synthetic config and running the normal rule set on it. Nothing is
 * executed or fetched.
 */
export function analyzeInstallSource(source: string): Finding[] {
  const json = { mcpServers: { 'install-candidate': { command: source } } };
  const target: ScanTarget = {
    file: '<install-candidate>',
    kind: 'mcp-config',
    raw: source,
    json,
    servers: extractServers(json, '<install-candidate>'),
    envVars: [],
  };
  return runRules([target]);
}

// ---------------------------------------------------------------------------
// Remote metadata analysis (network access is opt-in via --allow-network).
// Only JSON metadata is fetched over HTTPS; code is never downloaded or run.
// ---------------------------------------------------------------------------

export type InstallTarget =
  | { kind: 'npm'; name: string }
  | { kind: 'github'; repo: string }
  | { kind: 'unknown' };

const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

function stripVersion(token: string): string {
  const at = token.lastIndexOf('@');
  return at > 0 ? token.slice(0, at) : token;
}

/** Identify the npm package or GitHub repo referenced by an install source. */
export function parseInstallSource(source: string): InstallTarget {
  const s = source.trim();

  const npmPrefix = /^npm:(.+)$/.exec(s);
  if (npmPrefix?.[1]) return { kind: 'npm', name: stripVersion(npmPrefix[1].trim()) };

  const ghPrefix = /^github:([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)$/.exec(s);
  if (ghPrefix?.[1]) return { kind: 'github', repo: ghPrefix[1].replace(/\.git$/, '') };

  if (/^https?:\/\//.test(s)) {
    try {
      const url = new URL(s);
      if (url.hostname === 'github.com' || url.hostname === 'www.github.com') {
        const [owner, repo] = url.pathname.split('/').filter(Boolean);
        if (owner && repo)
          return { kind: 'github', repo: `${owner}/${repo.replace(/\.git$/, '')}` };
      }
    } catch {
      // fall through
    }
    return { kind: 'unknown' };
  }

  if (/\s/.test(s)) {
    // Looks like a command: take the first non-flag token after a runner verb.
    // Runner verbs (npx/dlx) take priority — in commands like
    // "claude mcp add notes -- npx -y notes-mcp" the npx argument is the
    // actual package, not the alias after "add".
    const tokens = s.split(/\s+/);
    const pickAfter = (verbs: ReadonlySet<string>): InstallTarget | undefined => {
      for (let i = 0; i < tokens.length; i++) {
        if (!verbs.has(tokens[i] ?? '')) continue;
        for (let j = i + 1; j < tokens.length; j++) {
          const tok = tokens[j] ?? '';
          if (tok.startsWith('-') || tok === '') continue;
          const name = stripVersion(tok);
          return NPM_NAME.test(name) ? { kind: 'npm', name } : undefined;
        }
      }
      return undefined;
    };
    return (
      pickAfter(new Set(['npx', 'dlx'])) ??
      pickAfter(new Set(['install', 'add', 'i'])) ?? { kind: 'unknown' }
    );
  }

  const bare = stripVersion(s);
  if (NPM_NAME.test(bare)) return { kind: 'npm', name: bare };
  return { kind: 'unknown' };
}

export interface RemoteSignal {
  level: 'high' | 'medium' | 'info';
  en: string;
  ja: string;
}

interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type FetchLike = (
  url: string,
  init?: { signal?: AbortSignal; headers?: Record<string, string> },
) => Promise<FetchResponse>;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const FETCH_TIMEOUT_MS = 8000;
const DAY_MS = 24 * 60 * 60 * 1000;

async function fetchJson(fetchImpl: FetchLike, url: string): Promise<FetchResponse> {
  return fetchImpl(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { accept: 'application/json', 'user-agent': 'aster-guard' },
  });
}

async function npmSignals(
  name: string,
  fetchImpl: FetchLike,
  now: number,
): Promise<RemoteSignal[]> {
  const signals: RemoteSignal[] = [];
  const res = await fetchJson(fetchImpl, `https://registry.npmjs.org/${name.replace('/', '%2F')}`);
  if (res.status === 404) {
    return [
      {
        level: 'high',
        en: `Package "${name}" does not exist on npm. AI tools sometimes suggest hallucinated names — and attackers register them later (slopsquatting).`,
        ja: `パッケージ「${name}」はnpmに存在しません。AIが幻覚で提案した名前の可能性があり、後からその名前を攻撃者が登録する手口（スロップスクワッティング）も知られています。`,
      },
    ];
  }
  if (!res.ok) {
    return [
      {
        level: 'info',
        en: `npm registry returned HTTP ${res.status} for "${name}"; could not verify the package.`,
        ja: `npmレジストリが HTTP ${res.status} を返したため、「${name}」を確認できませんでした。`,
      },
    ];
  }
  const meta = (await res.json()) as Record<string, unknown>;
  const distTags = isRecord(meta['dist-tags']) ? meta['dist-tags'] : {};
  const latest = typeof distTags.latest === 'string' ? distTags.latest : undefined;
  const versions = isRecord(meta.versions) ? meta.versions : {};
  const latestMeta =
    latest && isRecord(versions[latest]) ? (versions[latest] as Record<string, unknown>) : {};

  const scripts = isRecord(latestMeta.scripts) ? latestMeta.scripts : {};
  const installScripts = ['preinstall', 'install', 'postinstall'].filter(
    (k) => typeof scripts[k] === 'string',
  );
  if (installScripts.length > 0) {
    signals.push({
      level: 'high',
      en: `"${name}" runs code at install time (${installScripts.join(', ')} script). Review what it does before installing.`,
      ja: `「${name}」はインストール時にコードを実行します（${installScripts.join(', ')}スクリプト）。導入前に内容を必ず確認してください。`,
    });
  }

  const time = isRecord(meta.time) ? meta.time : {};
  const created = typeof time.created === 'string' ? Date.parse(time.created) : NaN;
  if (Number.isFinite(created) && now - created < 30 * DAY_MS) {
    signals.push({
      level: 'medium',
      en: `"${name}" was first published less than 30 days ago — very new packages deserve extra scrutiny.`,
      ja: `「${name}」は公開から30日未満の新しいパッケージです。新しすぎるパッケージは特に慎重に確認しましょう。`,
    });
  }

  if (typeof latestMeta.deprecated === 'string') {
    signals.push({
      level: 'medium',
      en: `"${name}" is deprecated: ${latestMeta.deprecated}`,
      ja: `「${name}」は非推奨（deprecated）です: ${latestMeta.deprecated}`,
    });
  }

  if (!latestMeta.repository && !meta.repository) {
    signals.push({
      level: 'info',
      en: `"${name}" has no repository link on npm — the source code cannot be easily reviewed.`,
      ja: `「${name}」はnpm上にリポジトリへのリンクがなく、ソースコードの確認がしにくい状態です。`,
    });
  }

  try {
    const dl = await fetchJson(
      fetchImpl,
      `https://api.npmjs.org/downloads/point/last-week/${name.replace('/', '%2F')}`,
    );
    if (dl.ok) {
      const data = (await dl.json()) as { downloads?: number };
      if (typeof data.downloads === 'number' && data.downloads < 100) {
        signals.push({
          level: 'medium',
          en: `"${name}" had only ${data.downloads} downloads last week — barely used packages are a common typosquatting vector.`,
          ja: `「${name}」の先週のダウンロード数は${data.downloads}件のみです。ほぼ使われていないパッケージはタイポスクワットの常套手段です。`,
        });
      }
    }
  } catch {
    // download stats are best-effort
  }
  return signals;
}

async function githubSignals(
  repo: string,
  fetchImpl: FetchLike,
  now: number,
): Promise<RemoteSignal[]> {
  const signals: RemoteSignal[] = [];
  const res = await fetchJson(fetchImpl, `https://api.github.com/repos/${repo}`);
  if (res.status === 404) {
    return [
      {
        level: 'high',
        en: `GitHub repository "${repo}" does not exist. Check the URL — it may be a typo or a hallucinated reference.`,
        ja: `GitHubリポジトリ「${repo}」は存在しません。タイプミスか、幻覚による参照の可能性があります。`,
      },
    ];
  }
  if (!res.ok) {
    return [
      {
        level: 'info',
        en: `GitHub API returned HTTP ${res.status} for "${repo}"; could not verify the repository.`,
        ja: `GitHub APIが HTTP ${res.status} を返したため、「${repo}」を確認できませんでした。`,
      },
    ];
  }
  const meta = (await res.json()) as Record<string, unknown>;
  if (meta.archived === true) {
    signals.push({
      level: 'medium',
      en: `"${repo}" is archived — it no longer receives fixes or security updates.`,
      ja: `「${repo}」はアーカイブ済みで、修正やセキュリティ更新は行われません。`,
    });
  }
  const pushedAt = typeof meta.pushed_at === 'string' ? Date.parse(meta.pushed_at) : NaN;
  if (Number.isFinite(pushedAt) && now - pushedAt > 365 * DAY_MS) {
    signals.push({
      level: 'medium',
      en: `"${repo}" has not been updated for over a year.`,
      ja: `「${repo}」は1年以上更新されていません。`,
    });
  }
  const stars = typeof meta.stargazers_count === 'number' ? meta.stargazers_count : undefined;
  if (stars !== undefined && stars < 5) {
    signals.push({
      level: 'info',
      en: `"${repo}" has ${stars} stars — little community review so far.`,
      ja: `「${repo}」のスター数は${stars}です。コミュニティによる検証はまだ少ない状態です。`,
    });
  }
  return signals;
}

/**
 * Fetch npm / GitHub metadata for an install source and derive risk signals.
 * Call this ONLY when the user explicitly allowed network access.
 */
export async function analyzeRemote(
  source: string,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
  now: number = Date.now(),
): Promise<RemoteSignal[]> {
  const target = parseInstallSource(source);
  if (target.kind === 'unknown') {
    return [
      {
        level: 'info',
        en: 'Could not identify an npm package or GitHub repository in the input; remote check skipped.',
        ja: '入力からnpmパッケージ／GitHubリポジトリを特定できなかったため、リモート検査はスキップしました。',
      },
    ];
  }
  try {
    return target.kind === 'npm'
      ? await npmSignals(target.name, fetchImpl, now)
      : await githubSignals(target.repo, fetchImpl, now);
  } catch (err) {
    return [
      {
        level: 'info',
        en: `Remote check failed: ${err instanceof Error ? err.message : String(err)}`,
        ja: `リモート検査に失敗しました: ${err instanceof Error ? err.message : String(err)}`,
      },
    ];
  }
}

/** Render remote signals as plain text lines (both languages for MCP, one for CLI). */
export function renderRemoteSignals(signals: RemoteSignal[], locale: 'ja' | 'en'): string[] {
  if (signals.length === 0) {
    return [
      locale === 'ja'
        ? 'リモート検査: 特に問題となるシグナルはありませんでした。'
        : 'Remote check: no concerning signals found.',
    ];
  }
  return signals.map((s) => `- [${s.level}] ${locale === 'ja' ? s.ja : s.en}`);
}
