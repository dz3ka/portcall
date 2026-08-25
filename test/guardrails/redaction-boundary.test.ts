import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');

/**
 * The redaction boundary (ADR-0005): renderers accept only `RedactedReport`, a
 * type branded with a private `unique symbol`. Exactly one `as RedactedReport`
 * cast should exist in the whole codebase, in `src/redact/index.ts` — that is
 * what makes it structurally impossible for a probe or renderer to fabricate a
 * redacted report without going through `redact()`.
 */

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

describe('redaction boundary guardrail', () => {
  it('has exactly one `as RedactedReport` cast, in src/redact/index.ts', async () => {
    const hits: { file: string; line: number }[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const text = await readFile(file, 'utf8');
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i += 1) {
        if (lines[i]?.includes('as RedactedReport')) {
          hits.push({ file: relative(SRC_ROOT, file).replace(/\\/g, '/'), line: i + 1 });
        }
      }
    }
    expect(hits).toHaveLength(1);
    expect(hits[0]?.file).toBe('redact/index.ts');
  });
});
