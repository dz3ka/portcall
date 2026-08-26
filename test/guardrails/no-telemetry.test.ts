import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');

/**
 * SPEC.md 4.3 / CLAUDE.md non-negotiable: no telemetry, ever. Static scan for
 * known analytics-host strings and for a module-scope outbound call (a fetch
 * or http request not inside a function — i.e. one that would fire merely on
 * import).
 */
const ANALYTICS_HOSTS: readonly string[] = [
  'google-analytics.com',
  'segment.io',
  'segment.com',
  'mixpanel.com',
  'amplitude.com',
  'sentry.io',
  'posthog.com',
  'fullstory.com',
  'datadoghq.com',
  'bugsnag.com',
];

/**
 * A module-scope outbound call: a statement whose *first* token opens a
 * request, so it fires on import rather than when some function is called.
 * Leading indentation is stripped before this runs — a beacon nested in a
 * top-level `try` or IIFE still runs at import time, and anchoring at column 0
 * would wave it through.
 */
const MODULE_SCOPE_CALL = /^(fetch\(|void fetch\(|http\.request\(|https\.request\()/;
/**
 * A TypeScript member signature is a declaration, not a statement: it opens no
 * socket. `src/net/types.ts` declares the `PacFetcher` seam as
 * `fetch(url: string, …): Promise<PacFetchOutcome>;`, which trips the pattern
 * above once indentation is stripped. Exempting the *shape* rather than the
 * file keeps every other line of `net/types.ts` under the check: a signature
 * is a parameter list followed by a return-type annotation and a terminating
 * `;`, with no body — a real beacon (`fetch('https://…')`) has no `): T;` tail
 * and so cannot hide here.
 */
const TYPE_MEMBER_SIGNATURE = /^[A-Za-z_$][\w$]*\(.*\)\s*:\s*[^;{]+;$/;

/** Module-scope call sites found in one file's source text. */
export function findModuleScopeCalls(text: string): string[] {
  const hits: string[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (TYPE_MEMBER_SIGNATURE.test(trimmed)) continue;
    if (MODULE_SCOPE_CALL.test(trimmed)) hits.push(trimmed);
  }
  return hits;
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

describe('no telemetry guardrail', () => {
  it('src/ contains no known analytics-host strings', async () => {
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const text = await readFile(file, 'utf8');
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      for (const host of ANALYTICS_HOSTS) {
        if (text.includes(host)) offenders.push(`${rel}: contains analytics host ${host}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('src/ contains no top-level (module-scope) fetch() or http request call', async () => {
    // A crude but honest check: a line that *starts* a `fetch(` or request
    // call is a statement, not an argument or a continuation — the shape a
    // telemetry beacon on load would take. It does not catch a beacon hidden
    // behind an assignment (`const _ = fetch(…)`) or an aliased binding; the
    // wall is `NetworkGuard`, this is the tripwire.
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const text = await readFile(file, 'utf8');
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      for (const hit of findModuleScopeCalls(text)) {
        offenders.push(`${rel}: module-scope network call: ${hit}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('catches a module-scope beacon indented inside a top-level try', () => {
    const beacon = "try {\n  void fetch('https://collector.example/e');\n} catch {}\n";
    expect(findModuleScopeCalls(beacon)).toEqual(["void fetch('https://collector.example/e');"]);
  });

  it('does not flag a type member signature named fetch', () => {
    const declaration =
      'export interface PacFetcher {\n' +
      '  fetch(url: string, options: { signal: AbortSignal }): Promise<PacFetchOutcome>;\n' +
      '}\n';
    expect(findModuleScopeCalls(declaration)).toEqual([]);
  });
});
