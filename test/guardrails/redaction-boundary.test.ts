import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { EvidenceKind } from '../../src/model/finding.ts';
import { redact } from '../../src/redact/index.ts';
import { buildReport, finding } from '../helpers/report-fixture.ts';

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

/**
 * The second half of the boundary: a kind that redaction has no opinion about
 * is a hole, because `redactEvidence` passes anything outside `SENSITIVE_KINDS`
 * through verbatim. The table below is `Record<EvidenceKind, boolean>`, so
 * adding a kind to `src/model/finding.ts` without deciding here whether it is
 * customer-identifying is a *typecheck* failure rather than a silent admission
 * - which is how `dn` (certificate distinguished names, M3) came to be listed.
 */
const HASHED_BY_DEFAULT: Readonly<Record<EvidenceKind, boolean>> = {
  hostname: true,
  ip: true,
  username: true,
  serial: true,
  path: true,
  url: true,
  // `CN=Acme Corp Internal Root, O=Acme Corp`: a private CA's name is the
  // customer's own organisation name, so it is hashed like any other identifier.
  dn: true,
  public: false,
  text: false,
  number: false,
};

describe('evidence kind redaction table', () => {
  it.each(Object.entries(HASHED_BY_DEFAULT))('kind %s is redacted: %s', (kind, hashed) => {
    const report = buildReport({}, [
      finding({ evidence: [{ label: kind, value: 'CN=Acme Corp Internal Root', kind: kind as EvidenceKind }] }),
    ]);
    const value = redact(report, { enabled: true, salt: 'fixed-salt' }).findings[0]?.evidence[0]?.value;

    expect(value).toBeDefined();
    if (hashed) {
      expect(value).toMatch(/^<[a-z]+:[0-9a-f]{12}>$/);
      expect(value).not.toContain('Acme Corp');
    } else {
      expect(value).toBe('CN=Acme Corp Internal Root');
    }
  });
});
