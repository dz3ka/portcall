import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');
const NET_DIR = join(SRC_ROOT, 'net');

/**
 * SPEC.md 4.3 / CLAUDE.md non-negotiable: no network calls except to hosts
 * named in the active profile. `net/guard.ts` is meant to be the sole gate, so
 * no module outside `src/net/` should import a raw networking API or call
 * `fetch` directly — every connection a probe opens should route through
 * `NetworkGuard`.
 */
const FORBIDDEN_IMPORTS: readonly RegExp[] = [
  /from\s+['"]node:net['"]/,
  /from\s+['"]node:tls['"]/,
  /from\s+['"]node:https['"]/,
  /from\s+['"]node:dgram['"]/,
  /from\s+['"]node:dns['"]/,
  /require\(\s*['"]node:net['"]\s*\)/,
  /require\(\s*['"]node:tls['"]\s*\)/,
  /require\(\s*['"]node:https['"]\s*\)/,
  /require\(\s*['"]node:dgram['"]\s*\)/,
  /require\(\s*['"]node:dns['"]\s*\)/,
];
/**
 * Any textual `fetch(` call, qualified or not. This is a grep, and it is worth
 * being plain about its reach:
 *
 *   caught   `fetch(url)`, `void fetch(url)`, `client.fetch(url)`,
 *            `{ fetch }` shorthand objects called back as `helper.fetch(url)`
 *   missed   a rebound identifier (`const f = fetch; f(url)`), a computed
 *            access (`globalThis['fetch'](url)`), and anything assembled at
 *            runtime — no text-level check can see those.
 *
 * The misses are inherent to scanning source as text; the real enforcement is
 * `NetworkGuard`, which every outbound connection must pass through at run
 * time. This test is the cheap second line, not the wall.
 */
const FORBIDDEN_FETCH = /\bfetch\(/;
/**
 * The `PacFetcher` seam (`src/net/types.ts`, M2) is itself named `.fetch()` so
 * its stub in tests reads naturally, and the proxy probe calls it as
 * `fetcher.fetch(...)` on the injected seam, never the global function.
 *
 * The exemption is scoped to that *location*, not to the token: stripping the
 * `fetcher.fetch(` shape everywhere would let any module launder a global
 * through an object named `fetcher` (`const fetcher = { fetch: globalThis.fetch }`
 * — the declaration line has no `(` to match, and the call site would be
 * stripped). Listing the one file that legitimately holds the seam keeps that
 * shape a failure everywhere else. Files, not line numbers: line numbers churn
 * with every edit to the probe and a guardrail that cries wolf gets deleted.
 * Inside a listed file only the exact `fetcher.fetch(` text is exempt — any
 * other `fetch(` there still trips — but a listed file could still declare its
 * own `fetcher` object over the global and be waved through, so keep the list
 * short and read those files when reviewing it.
 */
const SEAM_CALL_SITE_FILES: readonly string[] = ['probes/proxy/index.ts'];
const ALLOWED_FETCH_SEAM_CALL = /\bfetcher\.fetch\(/g;

/** Offenders found in one file's source text. `rel` is POSIX-style, relative to `src/`. */
export function scanForForbiddenNetworkUse(rel: string, text: string): string[] {
  const offenders: string[] = [];
  for (const pattern of FORBIDDEN_IMPORTS) {
    if (pattern.test(text)) offenders.push(`${rel}: forbidden import matching ${pattern.toString()}`);
  }
  const scannable = SEAM_CALL_SITE_FILES.includes(rel) ? text.replace(ALLOWED_FETCH_SEAM_CALL, '') : text;
  if (FORBIDDEN_FETCH.test(scannable)) offenders.push(`${rel}: bare fetch( call`);
  return offenders;
}

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      yield full;
    }
  }
}

describe('no network outside allowlist guardrail', () => {
  it('no module outside src/net/ imports a raw networking API or calls fetch()', async () => {
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      if (file.startsWith(NET_DIR + sep)) continue;
      const text = await readFile(file, 'utf8');
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      offenders.push(...scanForForbiddenNetworkUse(rel, text));
    }
    expect(offenders).toEqual([]);
  });

  it('catches a global laundered through an object named like the seam', () => {
    const impostor = 'const fetcher = { fetch: globalThis.fetch };\nawait fetcher.fetch(url);\n';
    expect(scanForForbiddenNetworkUse('probes/dns/index.ts', impostor)).toEqual([
      'probes/dns/index.ts: bare fetch( call',
    ]);
  });

  it('catches a bare fetch( in an allowlisted seam call site', () => {
    const mixed = 'await fetcher.fetch(pacUrl, options);\nconst sneaky = await fetch(url);\n';
    expect(scanForForbiddenNetworkUse('probes/proxy/index.ts', mixed)).toEqual([
      'probes/proxy/index.ts: bare fetch( call',
    ]);
  });

  it('allows the injected seam call in an allowlisted seam call site', () => {
    const seam = 'const outcome = await fetcher.fetch(pacUrl, { signal, guard, maxBytes });\n';
    expect(scanForForbiddenNetworkUse('probes/proxy/index.ts', seam)).toEqual([]);
  });

  /**
   * A seam exemption that outlives its call site is an unaudited hole. If the
   * probe stops calling the seam, delete the entry rather than leave it.
   */
  it('every allowlisted seam call site still contains the seam call', async () => {
    for (const rel of SEAM_CALL_SITE_FILES) {
      const text = await readFile(join(SRC_ROOT, ...rel.split('/')), 'utf8');
      expect(ALLOWED_FETCH_SEAM_CALL.test(text), `${rel}: stale seam exemption`).toBe(true);
      ALLOWED_FETCH_SEAM_CALL.lastIndex = 0;
    }
  });
});
