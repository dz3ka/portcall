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
const FORBIDDEN_FETCH = /\bfetch\(/;

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
      for (const pattern of FORBIDDEN_IMPORTS) {
        if (pattern.test(text)) offenders.push(`${rel}: forbidden import matching ${pattern.toString()}`);
      }
      if (FORBIDDEN_FETCH.test(text)) offenders.push(`${rel}: bare fetch( call`);
    }
    expect(offenders).toEqual([]);
  });
});
