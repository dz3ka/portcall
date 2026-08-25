import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { NetworkGuard } from '../src/net/guard.ts';
import type { DnsOutcome, DnsResolver, EndpointAttempt, EndpointProber, EndpointTarget } from '../src/net/types.ts';
import type { ProbeContext } from '../src/engine/index.ts';
import type { Finding } from '../src/model/finding.ts';
import { assertRemediable } from '../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../src/profiles/schema.ts';
import { dnsProbe, evaluateDoh, isSlowResolution, runDns } from '../src/probes/dns/index.ts';
import { SLOW_RESOLUTION_MS } from '../src/probes/dns/analyse.ts';

/**
 * Fixture-driven and network-free: the probe is handed a stub `DnsResolver` and
 * a stub `EndpointProber` through its default parameters, the same seam
 * `main(argv, streams)` uses. No test here contacts a host, DoH resolvers
 * included — the live run is a manual acceptance step.
 */

const DOH_DIR = join(import.meta.dirname, 'fixtures', 'doh');

async function attemptFixture(name: string): Promise<EndpointAttempt> {
  return JSON.parse(await readFile(join(DOH_DIR, name), 'utf8')) as EndpointAttempt;
}

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return { host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false, ...overrides };
}

function loaded(endpoints: Endpoint[], dohResolvers: string[] = []): LoadedProfile {
  const profile: Profile = {
    name: 'Fixture profile',
    endpoints,
    doh_resolvers: dohResolvers,
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
  };
}

function resolved(addresses: string[], elapsedMs = 20): DnsOutcome {
  return { ok: true, addresses, elapsedMs };
}

function resolverStub(outcome: DnsOutcome | ((host: string) => DnsOutcome)): DnsResolver {
  return {
    resolve: (host: string): Promise<DnsOutcome> =>
      Promise.resolve(typeof outcome === 'function' ? outcome(host) : outcome),
  };
}

/** Never called unless a test declares a DoH resolver. */
const noProber: EndpointProber = {
  attempt: (): Promise<EndpointAttempt> => {
    throw new Error('the prober must not be used when no DoH resolver is declared');
  },
};

function proberStub(attempt: EndpointAttempt, seen: EndpointTarget[] = []): EndpointProber {
  return {
    attempt: (target: EndpointTarget): Promise<EndpointAttempt> => {
      seen.push(target);
      return Promise.resolve(attempt);
    },
  };
}

function byId(findings: Finding[], id: string): Finding {
  const match = findings.find((finding) => finding.id === id);
  if (match === undefined) throw new Error(`no '${id}' finding in [${findings.map((f) => f.id).join(', ')}]`);
  return match;
}

function values(finding: Finding, kind: string): string[] {
  return finding.evidence.filter((item) => item.kind === kind).map((item) => item.value);
}

describe('dns probe', () => {
  it('is registered under the name every finding id is prefixed with', () => {
    expect(dnsProbe.name).toBe('dns');
  });

  it('reports a clean public answer as dns.resolved with every address as ip evidence', async () => {
    const findings = await runDns(
      context(loaded([endpoint()])),
      resolverStub(resolved(['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])),
      noProber,
    );

    expect(findings.map((finding) => finding.id)).toEqual(['dns.resolved']);
    const finding = byId(findings, 'dns.resolved');
    expect(finding.severity).toBe('ok');
    expect(finding.probe).toBe('dns');
    expect(values(finding, 'hostname')).toEqual(['api.example.com']);
    expect(values(finding, 'ip')).toEqual(['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']);
    expect(values(finding, 'number')).toEqual(['20']);
  });

  it('resolves each distinct profile host once, even when several endpoints share it', async () => {
    const hosts: string[] = [];
    const findings = await runDns(
      context(loaded([endpoint(), endpoint({ port: 80 }), endpoint({ host: 'cdn.example.com' })])),
      resolverStub((host) => {
        hosts.push(host);
        return resolved(['93.184.216.34']);
      }),
      noProber,
    );

    expect(hosts.sort()).toEqual(['api.example.com', 'cdn.example.com']);
    expect(findings).toHaveLength(2);
  });

  it('reports a resolver failure as dns.resolve-failed with the failure class and the code', async () => {
    const findings = await runDns(
      context(loaded([endpoint()])),
      resolverStub({ ok: false, code: 'ENOTFOUND', abortedBy: null, elapsedMs: 12 }),
      noProber,
    );

    const finding = byId(findings, 'dns.resolve-failed');
    expect(finding.severity).toBe('blocker');
    expect(values(finding, 'hostname')).toEqual(['api.example.com']);
    expect(values(finding, 'text')).toEqual(['name-not-found', 'ENOTFOUND']);
    expect(finding.remediation ?? '').not.toBe('');
  });

  it('caps a resolve failure on an optional endpoint at degraded', async () => {
    const findings = await runDns(
      context(loaded([endpoint({ required: false })])),
      resolverStub({ ok: false, code: 'SERVFAIL', abortedBy: null, elapsedMs: 12 }),
      noProber,
    );

    const finding = byId(findings, 'dns.resolve-failed');
    expect(finding.severity).toBe('degraded');
    expect(values(finding, 'text')).toEqual(['resolver-refused', 'SERVFAIL']);
  });

  it('reports a resolver watchdog timeout as a resolve failure, not as an abort', async () => {
    const findings = await runDns(
      context(loaded([endpoint()])),
      resolverStub({ ok: false, code: null, abortedBy: 'phase-timeout', elapsedMs: 5000 }),
      noProber,
    );

    const finding = byId(findings, 'dns.resolve-failed');
    expect(values(finding, 'text')[0]).toBe('resolver-timeout');
  });

  it('reports a private answer for a profile host as dns.split-horizon', async () => {
    const findings = await runDns(
      context(loaded([endpoint()])),
      resolverStub(resolved(['10.20.30.40', '93.184.216.34'])),
      noProber,
    );

    const finding = byId(findings, 'dns.split-horizon');
    expect(finding.severity).toBe('degraded');
    expect(values(finding, 'ip')).toEqual(['10.20.30.40', '93.184.216.34']);
    expect(values(finding, 'text')).toEqual(['private']);
    expect(finding.remediation ?? '').not.toBe('');
    expect(findings.map((f) => f.id)).not.toContain('dns.resolved');
  });

  it('reports a block address as dns.sinkholed, capped by whether the endpoint is required', async () => {
    const required = await runDns(context(loaded([endpoint()])), resolverStub(resolved(['0.0.0.0'])), noProber);
    expect(byId(required, 'dns.sinkholed').severity).toBe('blocker');
    expect(values(byId(required, 'dns.sinkholed'), 'ip')).toEqual(['0.0.0.0']);

    const optional = await runDns(
      context(loaded([endpoint({ required: false })])),
      resolverStub(resolved(['127.0.0.1'])),
      noProber,
    );
    expect(byId(optional, 'dns.sinkholed').severity).toBe('degraded');
  });

  it('treats SLOW_RESOLUTION_MS as inclusive: 499 is fine, 500 and 501 are slow', async () => {
    expect(SLOW_RESOLUTION_MS).toBe(500);
    expect([isSlowResolution(499), isSlowResolution(500), isSlowResolution(501)]).toEqual([false, true, true]);

    for (const [elapsedMs, slow] of [
      [499, false],
      [500, true],
      [501, true],
    ] as const) {
      const findings = await runDns(
        context(loaded([endpoint()])),
        resolverStub(resolved(['93.184.216.34'], elapsedMs)),
        noProber,
      );
      const ids = findings.map((finding) => finding.id);
      expect(ids.includes('dns.slow-resolution')).toBe(slow);
      if (slow) {
        const finding = byId(findings, 'dns.slow-resolution');
        expect(finding.severity).toBe('degraded');
        expect(values(finding, 'number')).toEqual([String(elapsedMs)]);
        expect(finding.remediation ?? '').not.toBe('');
      }
    }
  });

  it('reports a run-signal abort as dns.aborted and never as a network verdict', async () => {
    const findings = await runDns(
      context(loaded([endpoint()])),
      resolverStub({ ok: false, code: null, abortedBy: 'run-signal', elapsedMs: 900 }),
      noProber,
    );

    expect(findings.map((finding) => finding.id)).toEqual(['dns.aborted']);
    const finding = byId(findings, 'dns.aborted');
    expect(finding.severity).toBe('unknown');
    expect(values(finding, 'hostname')).toEqual(['api.example.com']);
  });

  it('emits nothing about DoH when the profile declares no resolvers', async () => {
    const findings = await runDns(context(loaded([endpoint()])), resolverStub(resolved(['93.184.216.34'])), noProber);
    expect(findings.filter((finding) => finding.id.startsWith('dns.doh'))).toEqual([]);
  });

  it('probes a declared DoH resolver on 443 with TLS', async () => {
    const seen: EndpointTarget[] = [];
    await runDns(
      context(loaded([endpoint()], ['dns.google'])),
      resolverStub(resolved(['93.184.216.34'])),
      proberStub(await attemptFixture('reachable.json'), seen),
    );

    expect(seen).toEqual([{ host: 'dns.google', port: 443, useTls: true }]);
  });

  it('emits one DoH finding per declared resolver, with the resolver in evidence and not in the id', async () => {
    const findings = await runDns(
      context(loaded([endpoint()], ['dns.google', 'cloudflare-dns.com'])),
      resolverStub(resolved(['93.184.216.34'])),
      proberStub(await attemptFixture('blocked-connect-refused.json')),
    );

    const doh = findings.filter((finding) => finding.id === 'dns.doh-blocked');
    expect(doh).toHaveLength(2);
    expect(doh.flatMap((finding) => values(finding, 'hostname'))).toEqual(['dns.google', 'cloudflare-dns.com']);
  });

  it.each([
    ['reachable.json', 'dns.doh-reachable', 'ok', 'reachable'],
    ['http-status-4xx.json', 'dns.doh-reachable', 'ok', 'reachable'],
    ['blocked-dns-enotfound.json', 'dns.doh-blocked', 'degraded', 'blocked-dns-failed'],
    ['blocked-dns-timeout.json', 'dns.doh-blocked', 'degraded', 'blocked-dns-timeout'],
    ['blocked-connect-refused.json', 'dns.doh-blocked', 'degraded', 'blocked-connect-refused'],
    ['blocked-connect-timeout.json', 'dns.doh-blocked', 'degraded', 'blocked-connect-timeout'],
    ['blocked-tls-failed.json', 'dns.doh-blocked', 'degraded', 'blocked-tls-failed'],
    ['run-signal.json', 'dns.doh-indeterminate', 'unknown', 'indeterminate-deadline'],
  ] as const)('maps the %s DoH attempt to %s', async (fixture, id, severity, outcome) => {
    const attempt = await attemptFixture(fixture);
    expect(evaluateDoh(attempt)).toBe(outcome);

    const findings = await runDns(
      context(loaded([endpoint()], ['dns.google'])),
      resolverStub(resolved(['93.184.216.34'])),
      proberStub(attempt),
    );

    const finding = byId(findings, id);
    expect(finding.severity).toBe(severity);
    expect(values(finding, 'text')).toEqual([outcome]);
    expect(values(finding, 'hostname')).toEqual(['dns.google']);
    if (severity !== 'ok') expect(finding.remediation ?? '').not.toBe('');
  });

  it('reports the reachable DoH endpoint with its TLS handshake time', async () => {
    const findings = await runDns(
      context(loaded([endpoint()], ['dns.google'])),
      resolverStub(resolved(['93.184.216.34'])),
      proberStub(await attemptFixture('reachable.json')),
    );

    expect(values(byId(findings, 'dns.doh-reachable'), 'number')).toEqual(['39']);
  });

  it('never claims DoH itself works, only that the resolver HTTPS endpoint is reachable', async () => {
    const findings = await runDns(
      context(loaded([endpoint()], ['dns.google'])),
      resolverStub(resolved(['93.184.216.34'])),
      proberStub(await attemptFixture('reachable.json')),
    );

    const title = byId(findings, 'dns.doh-reachable').title;
    expect(title).toMatch(/HTTPS endpoint/);
    expect(title).toMatch(/reachable/);
    expect(title).not.toMatch(/DoH works|DNS-over-HTTPS works/i);
  });

  it('keeps every host out of ids and titles, and every finding remediable', async () => {
    const findings = await runDns(
      context(loaded([endpoint(), endpoint({ host: 'cdn.example.com', required: false })], ['dns.google'])),
      resolverStub((host) => (host === 'cdn.example.com' ? resolved(['0.0.0.0']) : resolved(['10.0.0.1'], 800))),
      proberStub(await attemptFixture('blocked-tls-failed.json')),
    );

    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.probe).toBe('dns');
      expect(`${finding.id} ${finding.title}`).not.toMatch(/example\.com|dns\.google/);
      expect(() => {
        assertRemediable(finding);
      }).not.toThrow();
    }
  });
});
