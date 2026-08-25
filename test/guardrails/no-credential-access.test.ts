import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');

/**
 * SPEC.md 4.2 / CLAUDE.md non-negotiable: never read keychains, tokens,
 * private keys or browser profiles, and never prompt for a password. Static
 * text scan — this cannot prove absence of a clever obfuscation, but it is a
 * cheap trip-wire against the obvious mistake of a probe importing the wrong
 * thing to "just check whether a cert is trusted".
 */
const FORBIDDEN_PATTERNS: readonly RegExp[] = [
  /keychain/i,
  /security find-/i,
  /id_rsa/i,
  /\.ssh(?:[/\\]|['"`])/i,
  /Login Data/,
  /cookies\.sqlite/i,
  /\breadline\b/i,
  /wincred/i,
];

/**
 * `src/cli/help.ts` is required (SPEC.md 3, CLAUDE.md) to say plainly, in the
 * `--help` text, that portcall "never reads keychains, tokens, private keys
 * or browser profiles" — that is the negative disclosure the security team
 * reads, not an implementation. Flagging that sentence would be a false
 * positive against the exact promise this guardrail exists to hold the code
 * to, so it is the one allow-listed file, and only for that reason.
 */
const ALLOWLIST: ReadonlySet<string> = new Set(['cli/help.ts']);

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

describe('no credential access guardrail', () => {
  it('src/ contains none of the forbidden credential-access strings', async () => {
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      if (ALLOWLIST.has(rel)) continue;
      const text = await readFile(file, 'utf8');
      for (const pattern of FORBIDDEN_PATTERNS) {
        if (pattern.test(text)) offenders.push(`${rel}: matched ${pattern.toString()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the allow-listed help.ts only contains the negative disclosure, not an import', async () => {
    const text = await readFile(join(SRC_ROOT, 'cli', 'help.ts'), 'utf8');
    expect(text).toContain('never reads keychains');
    expect(text).not.toMatch(/require\(|from\s+['"].*keychain/i);
  });
});
