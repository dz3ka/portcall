import { describe, expect, it } from 'vitest';
import type { ProbeContext } from '../src/engine/index.ts';
import { assertRemediable } from '../src/model/finding.ts';
import type { Finding } from '../src/model/finding.ts';
import { NetworkGuard } from '../src/net/guard.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import type { TlsCapture, TlsCaptureTarget, TlsChainOutcome } from '../src/net/types.ts';
import type { Endpoint, LoadedProfile, Profile } from '../src/profiles/schema.ts';
import { runTls, tlsProbe } from '../src/probes/tls/index.ts';
import { derOfPem, subjectOfPem, syntheticChain } from './helpers/synthetic-chain.ts';

/**
 * The `tls` probe *shell* — the I/O edge, not the evaluation.
 *
 * What is exercised here is the shell's own job: which endpoints get captured,
 * whether the environment's proxy adds a second capture, and the
 * `tls.capture-failed-*` table for the four phases a capture can die in. The
 * chain verdicts belong to `test/tls-evaluate.test.ts`, which holds them
 * against synthetic DER with no socket anywhere near it; this file stubs
 * `TlsCapture` and asserts nothing about what a chain *means*.
 */

const NOW = new Date('2026-06-01T00:00:00.000Z');

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return { host: 'api.example.com', port: 443, purpose: 'fixture', required: true, expect_streaming: false, ...overrides };
}

function loaded(endpoints: Endpoint[]): LoadedProfile {
  const profile: Profile = {
    name: 'Fixture profile',
    endpoints,
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
  };
  return { id: 'fixture', source: 'builtin', profile };
}

function context(profile: LoadedProfile): ProbeContext {
  return {
    profile,
    net: new NetworkGuard(profile.profile),
    deadline: Date.now() + 60_000,
    signal: new AbortController().signal,
    observedAnchors: [],
  };
}

/** Answers every capture with the same outcome, recording what it was asked for. */
function capturerStub(outcome: TlsChainOutcome, seen: TlsCaptureTarget[] = []): TlsCapture {
  return {
    capture: (target: TlsCaptureTarget): Promise<TlsChainOutcome> => {
      seen.push(target);
      return Promise.resolve(outcome);
    },
  };
}

/**
 * A capture that succeeded, carrying a chain the evaluation can parse. Which
 * chain barely matters here - this file asserts on the shell's ids, never on a
 * verdict - so it is the privately-rooted shape, built the way
 * `test/tls-evaluate.test.ts` builds its own.
 */
async function capturedChain(): Promise<Extract<TlsChainOutcome, { ok: true }>> {
  const chainDer = await syntheticChain([
    { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp', dnsNames: ['api.example.com'] },
    { subject: 'CN=Acme Corp Internal Root, O=Acme Corp' },
  ]);
  return {
    ok: true,
    chainDer,
    negotiatedProtocol: 'TLSv1.3',
    negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
    requestedSni: 'api.example.com',
    timing: { connectMs: 4, tlsMs: 9 },
  };
}

function ids(findings: Finding[]): string[] {
  return findings.map((finding) => finding.id);
}

/**
 * `assertRemediable` only *requires* a remediation at `blocker`/`degraded`, and
 * every finding this shell emits is `unknown` - so it is run for the house rule
 * it encodes, and the stricter rule that applies here (CLAUDE.md: a finding a
 * reader cannot act on is not worth emitting) is asserted alongside it.
 */
function expectRemediable(findings: Finding[]): void {
  for (const finding of findings) {
    assertRemediable(finding);
    expect(finding.remediation?.trim()).toBeTruthy();
  }
}

function withId(findings: Finding[], id: string): Finding {
  const found = findings.find((finding) => finding.id === id);
  if (found === undefined) throw new Error(`no ${id} in [${ids(findings).join(', ')}]`);
  return found;
}

describe('tls probe shell', () => {
  it('is registered under the name every finding id is prefixed with', () => {
    expect(tlsProbe.name).toBe('tls');
  });

  it('captures once per distinct TLS endpoint, and not at all for a plaintext port', async () => {
    const seen: TlsCaptureTarget[] = [];
    await runTls(
      context(loaded([endpoint(), endpoint(), endpoint({ port: 80 }), endpoint({ host: 'other.example.com' })])),
      capturerStub(await capturedChain(), seen),
      {},
      NOW,
    );

    expect(seen).toEqual([
      { host: 'api.example.com', port: 443 },
      { host: 'other.example.com', port: 443 },
    ]);
  });

  it('adds a second capture through the proxy the environment names, and compares the two', async () => {
    const seen: TlsCaptureTarget[] = [];
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub(await capturedChain(), seen),
      { HTTPS_PROXY: 'http://proxy.corp.test:3128' },
      NOW,
    );

    expect(seen).toEqual([
      { host: 'api.example.com', port: 443 },
      { host: 'api.example.com', port: 443, viaProxy: { host: 'proxy.corp.test', port: 3128 } },
    ]);
    // Both chains came from the same stub, so the comparison is the identical
    // one - the shell's job here is only that the comparison happened at all.
    expect(ids(findings)).toContain('tls.chain-consistent');
  });

  it('does not compare paths when the environment names no proxy', async () => {
    const findings = await runTls(context(loaded([endpoint()])), capturerStub(await capturedChain()), {}, NOW);

    expect(ids(findings)).not.toContain('tls.chain-consistent');
    expect(ids(findings)).not.toContain('tls.intercepted-via-proxy');
  });

  it.each([
    ['dns', 'ENOTFOUND', 'tls.capture-failed-dns'],
    ['connect', 'ECONNREFUSED', 'tls.capture-failed-connect'],
    ['tunnel', 'HTTP_407', 'tls.capture-failed-tunnel'],
    ['tls', 'ECONNRESET', 'tls.capture-failed-tls'],
  ] as const)('reports a capture that died in the %s phase as %s', async (phase, code, id) => {
    // No proxy in the environment, so this is the direct leg answering with
    // each phase in turn: what is under test is the phase-to-verdict table,
    // not which leg a given phase can occur on.
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub({ ok: false, phase, code, abortedBy: null }),
      {},
      NOW,
    );

    const finding = withId(findings, id);
    expect(finding.probe).toBe('tls');
    // Never `blocker`: the check could not decide, and the reachability failure
    // underneath it is already reported by dns/egress at the right severity.
    expect(finding.severity).toBe('unknown');
    expect(finding.evidence).toContainEqual({ label: 'code', value: code, kind: 'text' });
    expectRemediable([finding]);
  });

  it.each([
    ['dns', /DNS team/i],
    ['connect', /outbound rule/i],
    ['tunnel', /never answered the CONNECT/i],
    ['tls', /inspection appliance/i],
  ] as const)('reports a capture that ran out of time in the %s phase as a timeout, not a coded failure', async (phase, remediation) => {
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub({ ok: false, phase, code: null, abortedBy: 'phase-timeout' }),
      {},
      NOW,
    );

    const finding = withId(findings, 'tls.capture-failed-timeout');
    expect(finding.probe).toBe('tls');
    expect(finding.severity).toBe('unknown');
    expect(finding.evidence).toContainEqual({ label: 'phase', value: phase, kind: 'text' });
    // The whole point of the separate id: a timeout has no code, and the
    // coded finding used to report our `unavailable` stand-in as if it did.
    expect(finding.evidence.map((item) => item.label)).not.toContain('code');
    // Four phases, four owners - the remediation names a different one each time.
    expect(finding.remediation).toMatch(remediation);
    expectRemediable([finding]);
    expect(ids(findings)).not.toContain('tls.capture-failed-' + phase);
  });

  it('says a 407 will not be answered, because portcall never authenticates', async () => {
    const chain = await capturedChain();
    const findings = await runTls(
      context(loaded([endpoint()])),
      {
        capture: (target: TlsCaptureTarget): Promise<TlsChainOutcome> =>
          Promise.resolve(
            target.viaProxy === undefined ? chain : { ok: false, phase: 'tunnel', code: 'HTTP_407', abortedBy: null },
          ),
      },
      { HTTPS_PROXY: 'http://proxy.corp.test:3128' },
      NOW,
    );

    const finding = withId(findings, 'tls.capture-failed-tunnel');
    expect(finding.remediation).toMatch(/never authenticates/i);
    expect(finding.evidence).toContainEqual({ label: 'proxy', value: 'proxy.corp.test', kind: 'hostname' });
  });

  it('reports a cancelled run as tls.aborted rather than as a verdict about the network', async () => {
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub({ ok: false, phase: 'tls', code: null, abortedBy: 'run-signal' }),
      {},
      NOW,
    );

    expect(ids(findings)).toEqual(['tls.aborted']);
    expectRemediable(findings);
  });

  it('reports each path separately when one succeeds and the other does not', async () => {
    const chain = await capturedChain();
    const capturer: TlsCapture = {
      capture: (target: TlsCaptureTarget): Promise<TlsChainOutcome> =>
        Promise.resolve(
          target.viaProxy === undefined ? chain : { ok: false, phase: 'tunnel', code: 'HTTP_403', abortedBy: null },
        ),
    };

    const findings = await runTls(
      context(loaded([endpoint()])),
      capturer,
      { HTTPS_PROXY: 'proxy.corp.test:3128' },
      NOW,
    );

    expect(ids(findings)).toContain('tls.capture-failed-tunnel');
    // A capture that failed is not evidence that the two paths agree.
    expect(ids(findings)).not.toContain('tls.chain-consistent');
    expect(findings.filter((finding) => finding.id.startsWith('tls.capture-failed'))).toHaveLength(1);
  });

  it('returns nothing at all for a profile with no TLS endpoint, rather than an empty verdict', async () => {
    const findings = await runTls(context(loaded([endpoint({ port: 80 })])), capturerStub(await capturedChain()), {}, NOW);

    expect(findings).toEqual([]);
  });

  it('emits a remediation on every finding it can produce', async () => {
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub({ ok: false, phase: 'connect', code: null, abortedBy: 'phase-timeout' }),
      { HTTP_PROXY: 'proxy.corp.test:8080' },
      NOW,
    );

    expect(findings).toHaveLength(2);
    expectRemediable(findings);
  });
});

/**
 * The proxied leg resolves and connects to the *proxy*, never to the endpoint:
 * `openTunnel` does the lookup and the TCP connect against `viaProxy`, and only
 * the tunnel and handshake that follow concern the endpoint at all. A `dns` or
 * `connect` verdict on that leg is therefore about a host the profile never
 * named, and a remediation that sends the reader to the endpoint's zone or asks
 * for a firewall rule to the endpoint's port sends them to the wrong team.
 */
describe('tls probe shell, on the leg that goes through a proxy', () => {
  const PROXY_ENV = { HTTPS_PROXY: 'http://proxy.corp.test:3128' };

  /** Succeeds directly and fails through the proxy, so the finding under test is unambiguously the proxied leg's. */
  function proxiedLegFails(
    chain: Extract<TlsChainOutcome, { ok: true }>,
    failure: Extract<TlsChainOutcome, { ok: false }>,
  ): TlsCapture {
    return {
      capture: (target: TlsCaptureTarget): Promise<TlsChainOutcome> =>
        Promise.resolve(target.viaProxy === undefined ? chain : failure),
    };
  }

  async function proxiedFailure(failure: Extract<TlsChainOutcome, { ok: false }>, id: string): Promise<Finding> {
    const findings = await runTls(
      context(loaded([endpoint()])),
      proxiedLegFails(await capturedChain(), failure),
      PROXY_ENV,
      NOW,
    );
    const finding = withId(findings, id);
    expect(finding.evidence).toContainEqual({ label: 'connection', value: 'proxy', kind: 'text' });
    return finding;
  }

  it('sends a name lookup that timed out to the zone the proxy lives in, not the endpoint\'s', async () => {
    const finding = await proxiedFailure(
      { ok: false, phase: 'dns', code: null, abortedBy: 'phase-timeout' },
      'tls.capture-failed-timeout',
    );

    expect(finding.remediation).toMatch(/serves the proxy's zone/);
    expect(finding.remediation).not.toMatch(/serves this zone/);
  });

  it('asks for an outbound rule to the proxy when the connect phase timed out, not to the endpoint', async () => {
    const finding = await proxiedFailure(
      { ok: false, phase: 'connect', code: null, abortedBy: 'phase-timeout' },
      'tls.capture-failed-timeout',
    );

    expect(finding.remediation).toMatch(/outbound rule to the proxy/);
    expect(finding.remediation).not.toMatch(/rule for this host and port/);
  });

  it('does not claim the dns probe corroborates a name that only this leg looked up', async () => {
    const finding = await proxiedFailure(
      { ok: false, phase: 'dns', code: 'ENOTFOUND', abortedBy: null },
      'tls.capture-failed-dns',
    );

    // False on this leg: the dns probe resolves the names the profile declares,
    // and the profile never named the proxy.
    expect(finding.remediation).not.toMatch(/the dns probe reports the same failure/);
    expect(finding.title).toMatch(/proxy name/i);
    expect(finding.remediation).toMatch(/dns probe/);
  });

  it('leaves the proxy host to the evidence, where redaction can reach it', async () => {
    for (const failure of [
      { ok: false, phase: 'dns', code: null, abortedBy: 'phase-timeout' },
      { ok: false, phase: 'connect', code: null, abortedBy: 'phase-timeout' },
      { ok: false, phase: 'dns', code: 'ENOTFOUND', abortedBy: null },
      { ok: false, phase: 'connect', code: 'ECONNREFUSED', abortedBy: null },
    ] as const) {
      const findings = await runTls(
        context(loaded([endpoint()])),
        proxiedLegFails(await capturedChain(), failure),
        PROXY_ENV,
        NOW,
      );
      for (const finding of findings) {
        // Remediation crosses the report boundary unredacted (`redactFinding`
        // copies it verbatim), so a customer's proxy name must never be in it.
        expect(finding.remediation ?? '').not.toContain('proxy.corp.test');
      }
    }
  });

  it('still names this endpoint and this zone when the same phases fail directly', async () => {
    const [timedOut, coded] = await Promise.all([
      runTls(
        context(loaded([endpoint()])),
        capturerStub({ ok: false, phase: 'dns', code: null, abortedBy: 'phase-timeout' }),
        {},
        NOW,
      ),
      runTls(context(loaded([endpoint()])), capturerStub({ ok: false, phase: 'dns', code: 'ENOTFOUND', abortedBy: null }), {}, NOW),
    ]);

    expect(withId(timedOut, 'tls.capture-failed-timeout').remediation).toMatch(/serves this zone/);
    expect(withId(coded, 'tls.capture-failed-dns').remediation).toMatch(/the dns probe reports the same failure for this host/);
  });

  it('does not claim the egress probe corroborates a port only this leg dialled', async () => {
    const finding = await proxiedFailure(
      { ok: false, phase: 'connect', code: 'ECONNREFUSED', abortedBy: null },
      'tls.capture-failed-connect',
    );

    // False on this leg for the same reason the dns cross-reference was: the
    // egress probe dials the profile's endpoints, and the proxy is not one.
    expect(finding.remediation).not.toMatch(/The egress probe reports the same failure/);
    expect(finding.remediation).toMatch(/egress probe is silent about it/);
    // The first sentence already covered both paths and stays as it was.
    expect(finding.remediation).toMatch(/or to the proxy in front of it/);
  });

  it('still sends a direct connect failure to the egress probe, which did dial that port', async () => {
    const findings = await runTls(
      context(loaded([endpoint()])),
      capturerStub({ ok: false, phase: 'connect', code: 'ECONNREFUSED', abortedBy: null }),
      {},
      NOW,
    );

    expect(withId(findings, 'tls.capture-failed-connect').remediation).toMatch(
      /The egress probe reports the same failure with the layer that stopped it/,
    );
  });
});

/**
 * The anchor observation seam at the edge (D3, ADR-0034). The shell is where
 * `evaluateChain`'s returned anchor becomes a push into the run-scoped array
 * the `truststore` probe reads, so this is where "one observation per path"
 * can be asserted at all - `test/tls-evaluate.test.ts` owns what an anchor
 * *contains*.
 */
describe('tls probe anchor observation', () => {
  /** A chain under a root the runtime ships, so the evaluation has nothing to observe. */
  async function publicOutcome(): Promise<Extract<TlsChainOutcome, { ok: true }>> {
    const rootPem = PUBLIC_ROOT_CA_PEMS[0] ?? '';
    const leaf = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: subjectOfPem(rootPem), dnsNames: ['api.example.com'] },
    ]);
    const direct = await capturedChain();
    return { ...direct, chainDer: [...leaf, derOfPem(rootPem)] };
  }

  it('records exactly one anchor for a privately rooted chain on a single path', async () => {
    const probeContext = context(loaded([endpoint()]));
    await runTls(probeContext, capturerStub(await capturedChain()), {}, NOW);

    expect(probeContext.observedAnchors).toHaveLength(1);
    expect(probeContext.observedAnchors[0]?.anchorClass).toBe('private');
    expect(probeContext.observedAnchors[0]?.via).toBe('direct');
    expect(probeContext.observedAnchors[0]?.host).toBe('api.example.com');
  });

  it('records nothing for a chain anchored in a root the runtime already ships', async () => {
    const probeContext = context(loaded([endpoint()]));
    await runTls(probeContext, capturerStub(await publicOutcome()), {}, NOW);

    expect(probeContext.observedAnchors).toEqual([]);
  });

  it('records one anchor per path when the same host is captured direct and through a proxy', async () => {
    const probeContext = context(loaded([endpoint()]));
    await runTls(
      probeContext,
      capturerStub(await capturedChain()),
      { HTTPS_PROXY: 'http://proxy.corp.test:3128' },
      NOW,
    );

    // Two paths to one host are two observations, not one deduplicated by
    // host: which path saw the anchor is what the cross-check correlates on.
    expect(probeContext.observedAnchors.map((anchor) => anchor.via)).toEqual(['direct', 'proxy']);
  });

  it('records nothing when every capture failed', async () => {
    const probeContext = context(loaded([endpoint()]));
    await runTls(probeContext, capturerStub({ ok: false, phase: 'connect', code: 'ECONNREFUSED', abortedBy: null }), {}, NOW);

    expect(probeContext.observedAnchors).toEqual([]);
  });
});
