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
    // A crude but honest check: a line starting a `fetch(` or request call at
    // column 0 (no leading whitespace) would run at import time, outside any
    // function — that is the shape a telemetry beacon on load would take.
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const text = await readFile(file, 'utf8');
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      for (const line of text.split('\n')) {
        if (/^(fetch\(|void fetch\(|http\.request\(|https\.request\()/.test(line.trim())) {
          offenders.push(`${rel}: module-scope network call: ${line.trim()}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
