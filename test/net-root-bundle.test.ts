import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import { fingerprintsOf } from './fixtures/tls/root-fingerprints.ts';

/**
 * ADR-0002 stakes this project's credibility on one claim: the same chain gets
 * the same verdict under Node and under the Bun-compiled binary. "Is this root
 * public or private" is answered against `PUBLIC_ROOT_CA_PEMS`, so if the two
 * runtimes ship different root lists, that verdict silently diverges by
 * runtime — a customer running the binary and an engineer running `npm run
 * dev` would be told different things about the same corporate proxy.
 *
 * That is not something a comment can hold, so it is measured: the same
 * fingerprint code runs in this process and again under `bun`, over the same
 * module, and the two sets must be identical.
 */

const PRINTER = join(import.meta.dirname, 'fixtures', 'tls', 'print-root-fingerprints.ts');

/** `null` when Bun is not installed here — the parity half then skips loudly rather than passing. */
function bunVersion(): string | null {
  const probe = spawnSync('bun', ['--version'], { encoding: 'utf8' });
  if (probe.error !== undefined || probe.status !== 0) return null;
  return probe.stdout.trim();
}

const BUN = bunVersion();
if (BUN === null) {
  console.info(
    '[net-root-bundle] bun is not on PATH here: the Node/Bun root-bundle parity check (ADR-0002) ' +
      'is SKIPPED, not passed. It runs wherever bun is installed, which since M3 includes the ci ' +
      '`verify` job on all three runners - so the claim is measured somewhere even when it is ' +
      'not measured here.',
  );
}

describe('PUBLIC_ROOT_CA_PEMS', () => {
  it('is a non-empty list of PEM certificates', () => {
    expect(PUBLIC_ROOT_CA_PEMS.length).toBeGreaterThan(0);
    for (const pem of PUBLIC_ROOT_CA_PEMS) {
      expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----/);
      expect(pem.trimEnd()).toMatch(/-----END CERTIFICATE-----$/);
    }
  });

  it('is plain data, not a live handle on the runtime', () => {
    // Every element is a string. Nothing here is a certificate *object* the
    // runtime built, which is what ADR-0002 forbids the evaluation layer from
    // reading — the classification downstream compares bytes, not objects.
    for (const pem of PUBLIC_ROOT_CA_PEMS) expect(typeof pem).toBe('string');
  });

  it('has no duplicate roots', () => {
    const fingerprints = fingerprintsOf(PUBLIC_ROOT_CA_PEMS);
    expect(new Set(fingerprints).size).toBe(fingerprints.length);
  });

  it.skipIf(BUN === null)('presents the identical root set under bun and under node (ADR-0002 parity)', () => {
    const printed = spawnSync('bun', [PRINTER], { encoding: 'utf8' });
    expect(printed.status, `bun exited ${String(printed.status)}: ${printed.stderr}`).toBe(0);

    const parsed: unknown = JSON.parse(printed.stdout.trim());
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toEqual(fingerprintsOf(PUBLIC_ROOT_CA_PEMS));
  });
});
