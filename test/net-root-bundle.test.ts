import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import { fingerprintsOf } from './fixtures/tls/root-fingerprints.ts';
import { fixtureAnchorsInRuntimeBundle, fixtureVerdicts } from './fixtures/tls/root-verdicts.ts';
import type { CrossRuntimeReport } from './fixtures/tls/root-verdicts.ts';

/**
 * This project's credibility rests on one claim: the same chain gets the same
 * verdict under Node and under the Bun-compiled binary customers run. "Is this
 * root public or private" is answered by `classifyRoot`, and if that answer
 * diverged by runtime, an engineer running `npm run dev` and a customer
 * running the binary would be told different things about the same corporate
 * proxy.
 *
 * That is a claim about *the verdict*, not about the runtimes' root bundles,
 * and it is measured as one (ADR-0031): portcall's own root evaluation runs in
 * this process and again under `bun`, over the same committed fixture chains
 * and the same fixed reference roots, and the two sets of verdicts must be
 * identical. Asserting the bundles themselves matched was never true - Node 22
 * ships 145 roots, Bun 121, Node 24 120 - and executed none of portcall's
 * logic under Bun, which is the runtime the shipped binary is built with.
 *
 * The one bundle claim that survives is narrow and real: the roots the
 * fixtures anchor in must ship in *both* runtimes, because a root in one list
 * and not the other flips `tls.public-root` to `tls.private-root` for the same
 * network.
 */

const PRINTER = join(import.meta.dirname, 'fixtures', 'tls', 'print-root-verdicts.ts');

/** `null` when Bun is not installed here — the parity half then skips loudly rather than passing. */
function bunVersion(): string | null {
  const probe = spawnSync('bun', ['--version'], { encoding: 'utf8' });
  if (probe.error !== undefined || probe.status !== 0) return null;
  return probe.stdout.trim();
}

const BUN = bunVersion();
if (BUN === null && process.env.CI !== undefined) {
  // Skip-when-absent is right for a bare laptop (ADR-0001), but CI installs bun
  // deliberately, so absence there means the install broke - and a broken install
  // must not buy a green run by silently skipping. ADR-0025: no permanent green lie.
  throw new Error(
    '[net-root-bundle] bun is not on PATH but CI is set: the ci `verify` job installs bun, so ' +
      'this means the install step failed. Failing loudly rather than skipping the Node/Bun ' +
      'parity check (ADR-0031) and reporting green.',
  );
}
if (BUN === null) {
  console.info(
    '[net-root-bundle] bun is not on PATH here: the Node/Bun root-bundle parity check (ADR-0031) ' +
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

});

describe('root verdicts under bun and under node', () => {
  it.skipIf(BUN === null)('reach the same answer over the same fixture chains (ADR-0031 parity)', () => {
    const printed = spawnSync('bun', [PRINTER], { encoding: 'utf8' });
    expect(printed.status, `bun exited ${String(printed.status)}: ${printed.stderr}`).toBe(0);

    const parsed = JSON.parse(printed.stdout.trim()) as CrossRuntimeReport;

    // The verdicts are portcall's own evaluation, run twice over pinned input.
    expect(parsed.verdicts).toEqual(fixtureVerdicts());

    // The anchors those fixtures depend on ship in both runtimes' bundles. Two
    // assertions, because each side answers for itself: this one for Node, the
    // printed one for Bun. The key sets are compared first so an empty object
    // cannot pass the loops vacuously.
    const anchors = fixtureAnchorsInRuntimeBundle();
    expect(Object.keys(parsed.anchorsInRuntimeBundle).sort()).toEqual(Object.keys(anchors).sort());

    for (const [subject, bundled] of Object.entries(parsed.anchorsInRuntimeBundle)) {
      expect(bundled, `${subject} is not in bun ${BUN ?? ''}'s root bundle`).toBe(true);
    }
    for (const [subject, bundled] of Object.entries(anchors)) {
      expect(bundled, `${subject} is not in this node's root bundle`).toBe(true);
    }
  });
});
