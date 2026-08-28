import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { NetworkGuard } from '../src/net/guard.ts';
import type { EndpointAttempt, EndpointProber, EndpointTarget } from '../src/net/types.ts';
import type { ProbeContext } from '../src/engine/index.ts';
import type { Finding } from '../src/model/finding.ts';
import { assertRemediable } from '../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../src/profiles/schema.ts';
import { egressProbe, runEgress } from '../src/probes/egress/index.ts';

/**
 * Fixture-driven and network-free: every case here is a recorded
 * `EndpointAttempt` handed to the probe through its stub `EndpointProber`, so
 * the finding table is exercised without a socket and without a platform
 * dependency. Codes that differ per OS (`ECONNRESET` on Windows where Linux
 * gives `EPIPE`) get one fixture each rather than one asserted string.
 */

const ATTEMPT_DIR = join(import.meta.dirname, 'fixtures', 'attempts');

async function attemptFixture(name: string): Promise<EndpointAttempt> {
  return JSON.parse(await readFile(join(ATTEMPT_DIR, name), 'utf8')) as EndpointAttempt;
}

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return { host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false, ...overrides };
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

function proberStub(attempt: EndpointAttempt, seen: EndpointTarget[] = []): EndpointProber {
  return {
    attempt: (target: EndpointTarget): Promise<EndpointAttempt> => {
      seen.push(target);
      return Promise.resolve(attempt);
    },
  };
}

function only(findings: Finding[]): Finding {
  expect(findings).toHaveLength(1);
  const first = findings[0];
  if (first === undefined) throw new Error('expected exactly one finding');
  return first;
}

function values(finding: Finding, kind: string): string[] {
  return finding.evidence.filter((item) => item.kind === kind).map((item) => item.value);
}

/** One endpoint, one recorded attempt, one finding. */
async function probeWith(fixture: string, overrides: Partial<Endpoint> = {}): Promise<Finding> {
  const findings = await runEgress(
    context(loaded([endpoint(overrides)])),
    proberStub(await attemptFixture(fixture)),
  );
  return only(findings);
}

describe('egress probe', () => {
  it('is registered under the name every finding id is prefixed with', () => {
    expect(egressProbe.name).toBe('egress');
  });

  it.each([
    ['ok-https.json', 'egress.reachable', 'ok'],
    ['ok-tcp-only.json', 'egress.reachable', 'ok'],
    ['http-proxy-status.json', 'egress.http-error', 'blocker'],
    ['dns-enotfound.json', 'egress.dns-failure', 'blocker'],
    ['connect-refused.json', 'egress.connect-refused', 'blocker'],
    ['connect-unreachable.json', 'egress.connect-unreachable', 'blocker'],
    ['connect-timeout.json', 'egress.connect-timeout', 'blocker'],
    ['timeout-dns-phase.json', 'egress.connect-timeout', 'blocker'],
    ['timeout-tls-phase.json', 'egress.connect-timeout', 'blocker'],
    ['timeout-http-phase.json', 'egress.connect-timeout', 'blocker'],
    ['connection-reset.json', 'egress.connection-reset', 'blocker'],
    ['connection-reset-epipe.json', 'egress.connection-reset', 'blocker'],
    ['tls-failure.json', 'egress.tls-failure', 'blocker'],
    ['http-parse-error.json', 'egress.http-error', 'blocker'],
    ['unclassified-eproto.json', 'egress.unclassified', 'unknown'],
    ['unclassified-no-code.json', 'egress.unclassified', 'unknown'],
    ['run-signal.json', 'egress.aborted', 'unknown'],
  ] as const)('maps the %s attempt to %s', async (fixture, id, severity) => {
    const finding = await probeWith(fixture);
    expect(finding.id).toBe(id);
    expect(finding.probe).toBe('egress');
    expect(finding.severity).toBe(severity);
    expect(values(finding, 'hostname')).toEqual(['api.example.com']);
    expect(values(finding, 'number')[0]).toBe('443');
    expect(`${finding.id} ${finding.title}`).not.toMatch(/example\.com/);
    expect(() => {
      assertRemediable(finding);
    }).not.toThrow();
  });

  it('reports a reachable HTTPS endpoint with its status, TLS protocol and elapsed time', async () => {
    const finding = await probeWith('ok-https.json');
    expect(values(finding, 'number')).toEqual(['443', '200', '147']);
    expect(values(finding, 'text')).toEqual(['TLSv1.3']);
    expect(finding.remediation).toBeUndefined();
  });

  it('reports a reachable non-HTTP port without inventing a status or a TLS protocol', async () => {
    const finding = await probeWith('ok-tcp-only.json', { port: 5432 });
    expect(finding.id).toBe('egress.reachable');
    expect(values(finding, 'number')).toEqual(['5432', '14']);
    expect(values(finding, 'text')).toEqual([]);
  });

  it('carries the failure code as text evidence where the finding table calls for one', async () => {
    expect(values(await probeWith('dns-enotfound.json'), 'text')).toEqual(['ENOTFOUND']);
    expect(values(await probeWith('connect-refused.json'), 'text')).toEqual(['ECONNREFUSED']);
    expect(values(await probeWith('connect-unreachable.json'), 'text')).toEqual(['EHOSTUNREACH']);
    expect(values(await probeWith('tls-failure.json'), 'text')).toEqual(['ERR_TLS_CERT_ALTNAME_INVALID']);
    expect(values(await probeWith('unclassified-eproto.json'), 'text')).toEqual(['EPROTO']);
  });

  it('names the phase a reset happened in, since that is who owns the appliance', async () => {
    expect(values(await probeWith('connection-reset.json'), 'text')).toEqual(['connect']);
    expect(values(await probeWith('connection-reset-epipe.json'), 'text')).toEqual(['http']);
  });

  it('cites the elapsed time on a silent drop, so the ticket can quote the timeout', async () => {
    expect(values(await probeWith('connect-timeout.json'), 'number')).toEqual(['443', '5009']);
    expect(values(await probeWith('timeout-dns-phase.json'), 'number')).toEqual(['443', '5000']);
    expect(values(await probeWith('timeout-tls-phase.json'), 'number')).toEqual(['443', '5038']);
  });

  it('names the phase a timeout fired in: the watchdog fires at three different layers', async () => {
    expect(values(await probeWith('connect-timeout.json'), 'text')).toEqual(['connect']);
    expect(values(await probeWith('timeout-dns-phase.json'), 'text')).toEqual(['dns']);
    expect(values(await probeWith('timeout-tls-phase.json'), 'text')).toEqual(['tls']);
    expect(values(await probeWith('timeout-http-phase.json'), 'text')).toEqual(['http']);
  });

  it('sends a timeout to the layer that stalled, and only the connect phase to the firewall', async () => {
    // A getaddrinfo that never returns is the DNS team, and a handshake that
    // hangs after a completed connect is an inline appliance. Reporting either
    // as a dropped SYN sends the operator to a firewall team with a ticket they
    // cannot action (CLAUDE.md: those layers are never collapsed).
    const connect = (await probeWith('connect-timeout.json')).remediation ?? '';
    expect(connect).toMatch(/outbound rule/);
    expect(connect).toMatch(/drop/);

    const dns = (await probeWith('timeout-dns-phase.json')).remediation ?? '';
    expect(dns).toMatch(/resolver/);
    expect(dns).not.toMatch(/outbound rule|dropping the packet/);

    const tls = (await probeWith('timeout-tls-phase.json')).remediation ?? '';
    expect(tls).toMatch(/handshake/);
    expect(tls).not.toMatch(/outbound rule|dropping the packet/);

    const http = (await probeWith('timeout-http-phase.json')).remediation ?? '';
    expect(http).toMatch(/headers/);
    expect(http).not.toMatch(/outbound rule|dropping the packet/);

    // The text renderer is plain ASCII: an em dash would render as mojibake.
    for (const remediation of [connect, dns, tls, http]) {
      expect(remediation).not.toMatch(/[^\x20-\x7E]/);
    }
  });

  it('reports the status an intermediary answered with', async () => {
    expect(values(await probeWith('http-proxy-status.json'), 'number')).toEqual(['443', '407']);
  });

  it('caps a blocker on an optional endpoint at degraded but never softens an unknown', async () => {
    expect((await probeWith('connect-refused.json', { required: false })).severity).toBe('degraded');
    expect((await probeWith('tls-failure.json', { required: false })).severity).toBe('degraded');
    expect((await probeWith('unclassified-eproto.json', { required: false })).severity).toBe('unknown');
    expect((await probeWith('run-signal.json', { required: false })).severity).toBe('unknown');
  });

  it('derives the HTTP layer from the port: TLS on 443, plaintext on 80, bare TCP elsewhere', async () => {
    const seen: EndpointTarget[] = [];
    await runEgress(
      context(loaded([endpoint(), endpoint({ port: 80 }), endpoint({ port: 5432 })])),
      proberStub(await attemptFixture('ok-tcp-only.json'), seen),
    );

    expect(seen).toEqual([
      { host: 'api.example.com', port: 443, useTls: true },
      { host: 'api.example.com', port: 80, useTls: false },
      { host: 'api.example.com', port: 5432, useTls: false },
    ]);
  });

  it('emits one finding per endpoint, and attempts every endpoint even when one fails', async () => {
    const seen: EndpointTarget[] = [];
    const findings = await runEgress(
      context(loaded([endpoint(), endpoint({ host: 'cdn.example.com', port: 80 })])),
      proberStub(await attemptFixture('connect-refused.json'), seen),
    );

    expect(seen).toHaveLength(2);
    expect(findings.map((finding) => finding.id)).toEqual(['egress.connect-refused', 'egress.connect-refused']);
    expect(findings.flatMap((finding) => values(finding, 'hostname'))).toEqual([
      'api.example.com',
      'cdn.example.com',
    ]);
  });

  it('emits nothing when the profile has no endpoints to reach', async () => {
    expect(await runEgress(context(loaded([])), proberStub(await attemptFixture('ok-https.json')))).toEqual([]);
  });
});
