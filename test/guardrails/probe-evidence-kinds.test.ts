import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { NetworkGuard, NetworkPolicyError } from '../../src/net/guard.ts';
import { extractCode } from '../../src/net/dns.ts';
import type { AttemptPhase, DnsOutcome, DnsResolver, EndpointAttempt, EndpointProber } from '../../src/net/types.ts';
import type { ProbeContext } from '../../src/engine/index.ts';
import type { ProbeErrorClass } from '../../src/engine/probe-error.ts';
import { probeErrorFinding } from '../../src/engine/probe-error.ts';
import type { Evidence, Finding } from '../../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../../src/profiles/schema.ts';
import type { AddressClass } from '../../src/probes/dns/analyse.ts';
import type { DohOutcome, ResolveFailure } from '../../src/probes/dns/index.ts';
import { runDns } from '../../src/probes/dns/index.ts';
import { runEgress } from '../../src/probes/egress/index.ts';

/**
 * SPEC.md 4.5 / ADR-0005: `text` evidence crosses the redaction boundary
 * *unhashed* (`src/redact/index.ts` hashes only the identifier kinds), so a
 * string that came from the network - a server header, a certificate subject,
 * a resolver's error prose, a TLS protocol name we do not recognise - reaching
 * `text` evidence would put peer-controlled content straight into a report the
 * customer forwards to a vendor. This guardrail asserts that never happens.
 *
 * The check has two halves, because probe `text` evidence has two shapes:
 *
 * 1. **Vocabulary.** Every value is a member of a closed set defined in our own
 *    source (`ResolveFailure`, `DohOutcome`, `AddressClass`, `AttemptPhase`,
 *    the TLS protocol allowlist) or one of our own literals. The sets below are
 *    typed as `Record<Union, true>`, so adding a member to the union in `src/`
 *    without adding it here fails the typecheck rather than silently widening
 *    what this test accepts.
 * 2. **Machine codes.** `code` evidence is the one value that is not a closed
 *    set - an OS errno space cannot be enumerated, and reporting the code
 *    verbatim is the point (`egress.unclassified` exists to say "we could not
 *    name this, here is the code"). It is bounded by *shape* instead, and the
 *    only producer of those codes, `extractCode`, is asserted to enforce that
 *    shape, so a resolver's error message can never become one.
 *
 * Every finding the M1 probes can produce is walked: both probes, every
 * recorded fixture, plus the resolver outcomes that have no fixture file.
 */

const ATTEMPT_DIR = join(import.meta.dirname, '..', 'fixtures', 'attempts');
const DOH_DIR = join(import.meta.dirname, '..', 'fixtures', 'doh');

/** Failure classes the DNS probe may name. Exhaustive by construction. */
const RESOLVE_FAILURES: Record<ResolveFailure, true> = {
  'name-not-found': true,
  'no-address-records': true,
  'resolver-timeout': true,
  'resolver-refused': true,
  unclassified: true,
};

/** DoH reachability verdicts. */
const DOH_OUTCOMES: Record<DohOutcome, true> = {
  reachable: true,
  'blocked-dns-failed': true,
  'blocked-dns-timeout': true,
  'blocked-connect-refused': true,
  'blocked-connect-timeout': true,
  'blocked-tls-failed': true,
  'indeterminate-deadline': true,
};

/** Address classes, reported as the `address class` evidence on a split-horizon answer. */
const ADDRESS_CLASSES: Record<AddressClass, true> = {
  public: true,
  private: true,
  sinkhole: true,
  malformed: true,
};

/** Attempt phases, reported as the `phase` evidence on a reset. Ours, not the peer's. */
const ATTEMPT_PHASES: Record<AttemptPhase, true> = { dns: true, connect: true, tls: true, http: true };

/**
 * How the engine classified a probe that threw. The class is the *only* thing
 * it may say about the error - the message is never read - so this union is the
 * whole of that finding's `text` vocabulary.
 */
const PROBE_ERROR_CLASSES: Record<ProbeErrorClass, true> = {
  'network-policy': true,
  aborted: true,
  unclassified: true,
};

/**
 * The TLS protocol names `src/probes/egress/index.ts` will let through. Kept as
 * a literal list rather than an import because the allowlist there is private
 * to that module - and the assertion that matters is the negative one below: a
 * protocol name outside it is dropped, not passed through.
 */
const TLS_PROTOCOLS = ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;

/** Our own stand-in for "the OS gave us no code". Never a remote string. */
const OUR_LITERALS = ['unavailable'] as const;

const TEXT_VOCABULARY: ReadonlySet<string> = new Set([
  ...Object.keys(RESOLVE_FAILURES),
  ...Object.keys(DOH_OUTCOMES),
  ...Object.keys(ADDRESS_CLASSES),
  ...Object.keys(ATTEMPT_PHASES),
  ...Object.keys(PROBE_ERROR_CLASSES),
  ...TLS_PROTOCOLS,
  ...OUR_LITERALS,
]);

/**
 * The shape `src/net/dns.ts` narrows every code to before it leaves the seam:
 * uppercase, underscores, digits, short. Prose, a hostname, a certificate
 * subject or a header value cannot survive it. Restated here on purpose - this
 * test is the thing that would notice if that narrowing were relaxed.
 */
const MACHINE_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

/** Labels whose value is a machine code rather than a word from our vocabulary. */
const CODE_LABELS: ReadonlySet<string> = new Set(['code']);

function isAllowedText(evidence: Evidence): boolean {
  if (TEXT_VOCABULARY.has(evidence.value)) return true;
  return CODE_LABELS.has(evidence.label) && MACHINE_CODE.test(evidence.value);
}

function offenders(findings: readonly Finding[]): string[] {
  return findings
    .flatMap((finding) => finding.evidence.map((evidence) => ({ finding, evidence })))
    .filter(({ evidence }) => evidence.kind === 'text' && !isAllowedText(evidence))
    .map(({ finding, evidence }) => `${finding.id}: ${evidence.label}=${JSON.stringify(evidence.value)}`);
}

function textValues(findings: readonly Finding[]): string[] {
  return findings.flatMap((finding) =>
    finding.evidence.filter((evidence) => evidence.kind === 'text').map((evidence) => evidence.value),
  );
}

// --- probe drivers ---------------------------------------------------------
// The same default-parameter seam `test/probe-*.test.ts` uses: recorded
// outcomes in, findings out, no socket.

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

function proberStub(attempt: EndpointAttempt): EndpointProber {
  return { attempt: (): Promise<EndpointAttempt> => Promise.resolve(attempt) };
}

function resolverStub(outcome: DnsOutcome): DnsResolver {
  return { resolve: (): Promise<DnsOutcome> => Promise.resolve(outcome) };
}

const noProber: EndpointProber = {
  attempt: (): Promise<EndpointAttempt> => {
    throw new Error('the prober must not be used when no DoH resolver is declared');
  },
};

async function fixtures(dir: string): Promise<EndpointAttempt[]> {
  const names = (await readdir(dir)).filter((name) => name.endsWith('.json'));
  expect(names.length).toBeGreaterThan(0);
  return Promise.all(
    names.map(async (name) => JSON.parse(await readFile(join(dir, name), 'utf8')) as EndpointAttempt),
  );
}

/** Both endpoint shapes: 443 (TLS + HTTP) and a bare port, which report differently. */
async function egressFindings(attempt: EndpointAttempt): Promise<Finding[]> {
  const required = await runEgress(context(loaded([endpoint()])), proberStub(attempt));
  const optional = await runEgress(
    context(loaded([endpoint({ port: 5432, required: false })])),
    proberStub(attempt),
  );
  return [...required, ...optional];
}

/**
 * Resolver outcomes have no fixture directory - they are three fields - so the
 * table is written out here, one row per `ResolveFailure` plus every answer
 * shape that produces a finding of its own.
 */
const RESOLVER_OUTCOMES: readonly DnsOutcome[] = [
  { ok: true, addresses: ['93.184.216.34'], elapsedMs: 20 },
  { ok: true, addresses: ['93.184.216.34'], elapsedMs: 5000 },
  { ok: true, addresses: ['10.1.2.3'], elapsedMs: 20 },
  { ok: true, addresses: ['127.0.0.1'], elapsedMs: 20 },
  { ok: true, addresses: [], elapsedMs: 20 },
  { ok: false, code: 'ENOTFOUND', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'ENODATA', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'ETIMEDOUT', abortedBy: null, elapsedMs: 5000 },
  { ok: false, code: 'SERVFAIL', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'EPROTO', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: null, abortedBy: 'phase-timeout', elapsedMs: 5000 },
  { ok: false, code: null, abortedBy: 'run-signal', elapsedMs: 30 },
  { ok: false, code: null, abortedBy: null, elapsedMs: 12 },
];

/**
 * Throws the engine's catch has to survive. Every one of them buries a
 * hostname, an address or an absolute path in `.message`, which is exactly why
 * `probeErrorFinding` never reads it.
 */
const HOSTILE_ERRORS: readonly unknown[] = [
  new NetworkPolicyError('build-07.corp.local', 8443),
  Object.assign(new Error('getaddrinfo ENOTFOUND internal.corp.example'), { code: 'ENOTFOUND' }),
  Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:443'), { code: 'ECONNREFUSED' }),
  Object.assign(new Error("ENOENT: no such file or directory, open '/home/jdoe/.config/portcall.yaml'"), {
    code: 'ENOENT',
  }),
  'boom: corp-proxy.internal refused',
  Object.assign(new Error('inspection gateway'), { name: 'CN=Corp TLS Inspection CA, O=Example Ltd' }),
];

describe('probe evidence kinds guardrail', () => {
  it('no engine probe-error finding carries text evidence from outside our own vocabulary', () => {
    const findings = HOSTILE_ERRORS.map((error) => probeErrorFinding('egress', error));

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no egress finding carries text evidence from outside our own vocabulary', async () => {
    const findings = (await Promise.all((await fixtures(ATTEMPT_DIR)).map(egressFindings))).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no dns finding carries text evidence from outside our own vocabulary', async () => {
    const findings = (
      await Promise.all(
        RESOLVER_OUTCOMES.map((outcome) =>
          runDns(context(loaded([endpoint()])), resolverStub(outcome), noProber),
        ),
      )
    ).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no doh finding carries text evidence from outside our own vocabulary', async () => {
    const profile = loaded([endpoint()], ['dns.example.com']);
    const findings = (
      await Promise.all(
        (await fixtures(DOH_DIR)).map((attempt) =>
          runDns(context(profile), resolverStub({ ok: true, addresses: ['93.184.216.34'], elapsedMs: 20 }), proberStub(attempt)),
        ),
      )
    ).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('drops a TLS protocol name it does not recognise rather than reporting it', async () => {
    const hostile = 'TLSv9.9 (openssl 3.0.2 / corp-inspection-gw)';
    const attempt: EndpointAttempt = {
      ok: true,
      addresses: ['93.184.216.34'],
      tlsProtocol: hostile,
      status: 200,
      timing: { dnsMs: 4, connectMs: 10, tlsMs: 20, httpMs: 30 },
    };

    const findings = await runEgress(context(loaded([endpoint()])), proberStub(attempt));

    expect(findings.map((finding) => finding.id)).toEqual(['egress.reachable']);
    expect(textValues(findings)).toEqual([]);
    expect(offenders(findings)).toEqual([]);
  });

  it('reports a recognised TLS protocol, so the filter above is a filter and not a blanket drop', async () => {
    const attempt: EndpointAttempt = {
      ok: true,
      addresses: ['93.184.216.34'],
      tlsProtocol: 'TLSv1.3',
      status: 200,
      timing: { dnsMs: 4, connectMs: 10, tlsMs: 20, httpMs: 30 },
    };

    const findings = await runEgress(context(loaded([endpoint()])), proberStub(attempt));

    expect(textValues(findings)).toEqual(['TLSv1.3']);
  });

  it('would reject a remote string that reached code evidence', () => {
    // The vocabulary rule has one hole by design - `code` - so the shape rule
    // that plugs it is asserted directly, on the strings this exists to stop.
    for (const hostile of [
      'Server: nginx/1.25.3 (Ubuntu)',
      'unable to verify the first certificate for corp-proxy.internal',
      'CN=Corp TLS Inspection CA, O=Example Ltd',
      'ECONNREFUSED connecting to 10.1.2.3:443',
    ]) {
      expect(isAllowedText({ label: 'code', value: hostile, kind: 'text' })).toBe(false);
    }
  });

  it('the seam that produces code evidence emits nothing but a machine code', () => {
    // `extractCode` is the only source of the `code` field on an attempt or a
    // resolver outcome, so the shape rule above holds only as long as it does.
    expect(extractCode(Object.assign(new Error('handshake failed'), { code: 'ECONNRESET' }))).toBe('ECONNRESET');
    expect(extractCode({ code: 'Server: nginx/1.25.3 (Ubuntu)' })).toBeNull();
    expect(extractCode({ code: 'CN=Corp TLS Inspection CA' })).toBeNull();
    expect(extractCode(new Error('unable to verify the first certificate'))).toBeNull();
    expect(extractCode({ code: 'E'.repeat(65) })).toBeNull();
  });

  it('accepts every machine code the M1 fixtures carry', async () => {
    const codes = (await fixtures(ATTEMPT_DIR))
      .map((attempt) => (attempt.ok ? null : attempt.code))
      .filter((code): code is string => code !== null);

    expect(codes.length).toBeGreaterThan(0);
    for (const code of codes) expect(MACHINE_CODE.test(code)).toBe(true);
  });
});
