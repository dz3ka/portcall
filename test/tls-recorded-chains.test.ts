import { describe, expect, it } from 'vitest';
import type { ProbeContext } from '../src/engine/index.ts';
import { assertRemediable } from '../src/model/finding.ts';
import type { Finding, Severity } from '../src/model/finding.ts';
import { NetworkGuard } from '../src/net/guard.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import type { TlsCapture, TlsCaptureTarget, TlsChainOutcome } from '../src/net/types.ts';
import type { LoadedProfile, Profile } from '../src/profiles/schema.ts';
import { runTls } from '../src/probes/tls/index.ts';
import { publicRootIndex } from '../src/probes/tls/public-roots.ts';
import { RECORDED_CONDITIONS, loadRecordedChain, recordedChainPath } from './fixtures/tls/recorded-chains.ts';
import type { RecordedCapture, RecordedChain, RecordedCondition } from './fixtures/tls/recorded-chains.ts';

/**
 * The four conditions SPEC.md §10 names as recorded fixtures - public,
 * intercepted, expired, wrong-SNI - driven through the probe from the
 * committed chains in `test/fixtures/tls/chains/`.
 *
 * This is the unit half of the hostile-network harness: the same four
 * conditions `docker compose` will produce live, held against the exact
 * finding id *and* severity each one has to yield. The ids are API (CLAUDE.md),
 * so the assertion is the whole ordered list of `id`/`severity` pairs a run
 * produces rather than a `toContain` that would not notice a finding appearing,
 * disappearing or changing weight beside the one under test.
 *
 * It drives `runTls` and not `evaluateChain`, because the shell is where the
 * two paths are stitched together and where a fixture's proxied capture becomes
 * an interception verdict. The capture layer is replaced by a replay of the
 * fixture; nothing here opens a socket. Sweeps around each verdict (wildcards,
 * the expiry window's edges, every protocol rank) stay in
 * `test/tls-evaluate.test.ts`, where varying one dimension is cheaper than a
 * committed file per point.
 */

const HOST = 'api.example.com';

interface ProfileShape {
  required?: boolean;
  interceptionTolerated?: boolean;
}

function loaded({ required = true, interceptionTolerated = false }: ProfileShape = {}): LoadedProfile {
  const profile: Profile = {
    name: 'Fixture profile',
    endpoints: [{ host: HOST, port: 443, purpose: 'api', required, expect_streaming: false }],
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: interceptionTolerated },
  };
  return { id: 'fixture', source: 'builtin', profile };
}

function context(profile: LoadedProfile): ProbeContext {
  return {
    profile,
    net: new NetworkGuard(profile.profile),
    deadline: Date.now() + 60_000,
    signal: new AbortController().signal,
  };
}

function outcome(capture: RecordedCapture): TlsChainOutcome {
  return { ok: true, ...capture, timing: { connectMs: 7, tlsMs: 21 } };
}

/**
 * Replays a fixture: the direct capture for a direct target, the proxied one
 * for a tunnelled target. A fixture with no proxied capture that is asked for
 * one is a test wired wrong, and says so rather than answering with the direct
 * chain - which would silently turn an interception assertion into a
 * comparison of a chain with itself.
 */
function replay(fixture: RecordedChain): TlsCapture {
  return {
    capture: (target: TlsCaptureTarget): Promise<TlsChainOutcome> => {
      if (target.viaProxy === undefined) return Promise.resolve(outcome(fixture.direct));
      if (fixture.viaProxy === null) throw new Error(`the ${fixture.condition} fixture recorded no proxied capture`);
      return Promise.resolve(outcome(fixture.viaProxy));
    },
  };
}

/** A proxy is named to the shell only when the fixture has a proxied capture to replay. */
function run(fixture: RecordedChain, profile: ProfileShape = {}): Promise<Finding[]> {
  return runTls(
    context(loaded(profile)),
    replay(fixture),
    fixture.viaProxy === null ? {} : { HTTPS_PROXY: 'http://proxy.corp.test:3128' },
    fixture.capturedAt,
  );
}

function verdicts(findings: readonly Finding[]): string[] {
  return findings.map((finding) => `${finding.id}=${finding.severity}`);
}

interface MatrixRow {
  condition: RecordedCondition;
  expected: readonly `${string}=${Severity}`[];
}

/** One row per SPEC.md §10 condition, against a profile that requires the endpoint and tolerates nothing. */
const MATRIX: readonly MatrixRow[] = [
  { condition: 'public', expected: ['tls.public-root=ok', 'tls.protocol=ok'] },
  {
    condition: 'intercepted',
    expected: [
      // The direct path is clean; the proxied one is re-signed under a CA the
      // runtime does not ship, and the comparison of the two leaves is the
      // finding that rests on no trust judgement at all.
      'tls.public-root=ok',
      'tls.protocol=ok',
      'tls.private-root=blocker',
      'tls.protocol=ok',
      'tls.intercepted-via-proxy=degraded',
    ],
  },
  { condition: 'expired', expected: ['tls.public-root=ok', 'tls.protocol=ok', 'tls.chain-expired=blocker'] },
  { condition: 'wrong-sni', expected: ['tls.public-root=ok', 'tls.protocol=ok', 'tls.sni-mismatch=blocker'] },
];

describe('recorded chain fixtures', () => {
  it.each(RECORDED_CONDITIONS)('reads the %s fixture back as the bytes that were recorded', (condition) => {
    const fixture = loadRecordedChain(condition);

    expect(fixture.condition).toBe(condition);
    expect(fixture.host).toBe(HOST);
    expect(fixture.summary.length).toBeGreaterThan(0);
    for (const der of fixture.direct.chainDer) expect(der.byteLength).toBeGreaterThan(64);
  });

  /**
   * Three of the four fixtures are anchored in a root taken from the runtime's
   * *own* bundle, so `tls.public-root` depends on that root still shipping.
   * When a future Node drops it the matrix below would fail as
   * `tls.private-root`, which reads like a product regression and is not one -
   * so the dependency is asserted directly, and the failure names itself and
   * says how to re-record.
   */
  it('is still anchored in a root this runtime ships', () => {
    const roots = publicRootIndex(PUBLIC_ROOT_CA_PEMS);
    const anchored = RECORDED_CONDITIONS.map(loadRecordedChain).filter((fixture) => fixture.publicAnchor !== null);

    expect(anchored.length).toBeGreaterThan(0);
    for (const fixture of anchored) {
      const anchor = fixture.direct.chainDer.at(-1);
      expect(
        anchor !== undefined && roots.hasCertificate(anchor),
        `${fixture.publicAnchor ?? ''} is no longer in this runtime's root bundle; re-record ` +
          `${recordedChainPath(fixture.condition)} with test/fixtures/tls/record-chains.ts`,
      ).toBe(true);
    }
  });
});

describe('the four conditions SPEC.md §10 records', () => {
  it.each(MATRIX)('$condition yields exactly its findings', async ({ condition, expected }) => {
    const findings = await run(loadRecordedChain(condition));

    expect(verdicts(findings)).toEqual([...expected]);
    for (const finding of findings) {
      expect(finding.probe).toBe('tls');
      assertRemediable(finding);
    }
  });

  it('reports the matched root by name on the public fixture, because a public CA is public knowledge', async () => {
    const fixture = loadRecordedChain('public');
    const finding = (await run(fixture)).find((candidate) => candidate.id === 'tls.public-root');
    const root = finding?.evidence.find((evidence) => evidence.label === 'root');

    expect(root?.kind).toBe('public');
    expect(root?.value).toBe(fixture.publicAnchor);
  });

  it('degrades the intercepted verdict instead of blocking when the profile tolerates interception', async () => {
    const findings = await run(loadRecordedChain('intercepted'), { interceptionTolerated: true });

    expect(verdicts(findings)).toContain('tls.private-root=degraded');
    // Not softened by the same knob: the comparison reports a fact about bytes
    // and has no profile to read.
    expect(verdicts(findings)).toContain('tls.intercepted-via-proxy=degraded');
  });

  it.each(['intercepted', 'expired', 'wrong-sni'] as const)(
    'caps the %s blocker to degraded for an endpoint the profile does not require',
    async (condition) => {
      const findings = await run(loadRecordedChain(condition), { required: false });

      expect(findings.filter((finding) => finding.severity === 'blocker')).toEqual([]);
      expect(verdicts(findings).some((verdict) => verdict.endsWith('=degraded'))).toBe(true);
    },
  );

  it('carries the private CA name as a `dn`, never as free text', async () => {
    const findings = await run(loadRecordedChain('intercepted'));
    const named = findings
      .flatMap((finding) => finding.evidence)
      .filter((evidence) => evidence.value.includes('Interception'));

    expect(named.length).toBeGreaterThan(0);
    for (const evidence of named) expect(evidence.kind).toBe('dn');
  });
});
