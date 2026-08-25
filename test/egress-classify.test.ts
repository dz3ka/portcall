import { describe, expect, it } from 'vitest';
import { cap, classifyAttempt, classifyStatus } from '../src/probes/egress/classify.ts';
import type { EgressClass } from '../src/probes/egress/classify.ts';
import type { AttemptPhase, AttemptTiming, EndpointAttempt } from '../src/net/types.ts';
import type { Severity } from '../src/model/finding.ts';

const NO_TIMING: AttemptTiming = { dnsMs: null, connectMs: null, tlsMs: null, httpMs: null };

function failed(
  phase: AttemptPhase,
  code: string | null,
  abortedBy: 'phase-timeout' | 'run-signal' | null = null,
): EndpointAttempt {
  return { ok: false, phase, code, abortedBy, addresses: [], status: null, timing: NO_TIMING };
}

interface AttemptCase {
  readonly label: string;
  readonly attempt: EndpointAttempt;
}

/**
 * The error -> class table, keyed by `EgressClass`.
 *
 * The `Record<EgressClass, ...>` annotation is the exhaustiveness guard: adding
 * a member to `EgressClass` without adding a row here is a compile error. The
 * runtime test below then asserts that every key is actually *produced* by one
 * of its own rows, so a dead row cannot sit here looking like coverage.
 */
const CASES: Record<EgressClass, readonly AttemptCase[]> = {
  ok: [
    {
      label: 'a successful attempt',
      attempt: { ok: true, addresses: ['93.184.216.34'], tlsProtocol: 'TLSv1.3', status: 200, timing: NO_TIMING },
    },
    {
      label: 'a successful attempt carrying a proxy status (classifyStatus judges that, not us)',
      attempt: { ok: true, addresses: [], tlsProtocol: null, status: 407, timing: NO_TIMING },
    },
  ],
  dns: [
    { label: 'ENOTFOUND', attempt: failed('dns', 'ENOTFOUND') },
    { label: 'EAI_AGAIN', attempt: failed('dns', 'EAI_AGAIN') },
    { label: 'EAI_NODATA', attempt: failed('dns', 'EAI_NODATA') },
    { label: 'ENODATA', attempt: failed('dns', 'ENODATA') },
    { label: 'NXDOMAIN', attempt: failed('dns', 'NXDOMAIN') },
    { label: 'SERVFAIL', attempt: failed('dns', 'SERVFAIL') },
    { label: 'REFUSED (the DNS rcode, not ECONNREFUSED)', attempt: failed('dns', 'REFUSED') },
    { label: 'ETIMEOUT', attempt: failed('dns', 'ETIMEOUT') },
    {
      label: 'a DNS-phase code outranks the phase-timeout flag: still the DNS team',
      attempt: failed('dns', 'ETIMEOUT', 'phase-timeout'),
    },
  ],
  refused: [
    { label: 'ECONNREFUSED on connect', attempt: failed('connect', 'ECONNREFUSED') },
    { label: 'ECONNREFUSED on any phase', attempt: failed('http', 'ECONNREFUSED') },
  ],
  unreachable: [
    { label: 'EHOSTUNREACH', attempt: failed('connect', 'EHOSTUNREACH') },
    { label: 'ENETUNREACH', attempt: failed('connect', 'ENETUNREACH') },
    { label: 'ENETDOWN', attempt: failed('connect', 'ENETDOWN') },
    { label: 'EADDRNOTAVAIL', attempt: failed('connect', 'EADDRNOTAVAIL') },
  ],
  timeout: [
    { label: 'ETIMEDOUT', attempt: failed('connect', 'ETIMEDOUT') },
    { label: 'ERR_SOCKET_CONNECTION_TIMEOUT', attempt: failed('connect', 'ERR_SOCKET_CONNECTION_TIMEOUT') },
    { label: 'a phase-timeout abort with no code at all', attempt: failed('connect', null, 'phase-timeout') },
    {
      label: 'a phase-timeout abort outranks the code: ECONNRESET on tls is still a timeout',
      attempt: failed('tls', 'ECONNRESET', 'phase-timeout'),
    },
    { label: 'a phase-timeout abort on the http phase', attempt: failed('http', 'EPIPE', 'phase-timeout') },
    {
      label: 'a dns-phase watchdog with no code at all: the resolver never answered',
      attempt: failed('dns', null, 'phase-timeout'),
    },
    {
      label: 'a tls-phase watchdog with no code at all: a handshake that hangs after connect',
      attempt: failed('tls', null, 'phase-timeout'),
    },
  ],
  reset: [
    { label: 'ECONNRESET on connect', attempt: failed('connect', 'ECONNRESET') },
    { label: 'EPIPE on connect', attempt: failed('connect', 'EPIPE') },
    { label: 'ECONNRESET on http', attempt: failed('http', 'ECONNRESET') },
    { label: 'EPIPE on http', attempt: failed('http', 'EPIPE') },
  ],
  tls: [
    { label: 'ECONNRESET on tls, which is interception and not a plain reset', attempt: failed('tls', 'ECONNRESET') },
    { label: 'EPIPE on tls', attempt: failed('tls', 'EPIPE') },
    { label: 'the ERR_TLS_ prefix', attempt: failed('tls', 'ERR_TLS_HANDSHAKE_TIMEOUT') },
    { label: 'the ERR_SSL_ prefix', attempt: failed('tls', 'ERR_SSL_WRONG_VERSION_NUMBER') },
    { label: 'the CERT_ prefix', attempt: failed('tls', 'CERT_HAS_EXPIRED') },
    { label: 'DEPTH_ZERO_SELF_SIGNED_CERT', attempt: failed('tls', 'DEPTH_ZERO_SELF_SIGNED_CERT') },
    { label: 'SELF_SIGNED_CERT_IN_CHAIN', attempt: failed('tls', 'SELF_SIGNED_CERT_IN_CHAIN') },
    { label: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', attempt: failed('tls', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') },
    { label: 'ERR_TLS_CERT_ALTNAME_INVALID', attempt: failed('tls', 'ERR_TLS_CERT_ALTNAME_INVALID') },
  ],
  http: [
    { label: 'the HPE_ prefix', attempt: failed('http', 'HPE_INVALID_CONSTANT') },
    { label: 'the ERR_HTTP_ prefix', attempt: failed('http', 'ERR_HTTP_INVALID_STATUS_CODE') },
  ],
  unclassified: [
    { label: 'a code no table row claims', attempt: failed('connect', 'EPROTOTYPE') },
    { label: 'no code at all', attempt: failed('connect', null) },
    {
      label: 'a run-signal abort (WP4 catches this before us; reaching us, we still do not guess)',
      attempt: failed('connect', null, 'run-signal'),
    },
    { label: 'a TLS code on the http phase, because phase rows are phase-scoped', attempt: failed('http', 'ERR_TLS_FOO') },
    { label: 'an HTTP parser code on the connect phase', attempt: failed('connect', 'HPE_INVALID_CONSTANT') },
    { label: 'a DNS rcode outside the dns phase', attempt: failed('connect', 'SERVFAIL') },
  ],
};

const ROWS = (Object.keys(CASES) as EgressClass[]).flatMap((expected) =>
  CASES[expected].map((testCase) => [expected, testCase.label, testCase.attempt] as const),
);

describe('classifyAttempt', () => {
  it.each(ROWS)('is %s for %s', (expected, _label, attempt) => {
    expect(classifyAttempt(attempt)).toBe(expected);
  });

  it('produces every EgressClass member from its own table rows', () => {
    const declared = Object.keys(CASES).sort();
    const produced = [...new Set(ROWS.map(([, , attempt]) => classifyAttempt(attempt)))].sort();
    expect(produced).toEqual(declared);
  });

  it('splits ECONNRESET by phase: tls means interception, connect and http mean a reset', () => {
    expect(classifyAttempt(failed('tls', 'ECONNRESET'))).toBe('tls');
    expect(classifyAttempt(failed('connect', 'ECONNRESET'))).toBe('reset');
    expect(classifyAttempt(failed('http', 'ECONNRESET'))).toBe('reset');
  });
});

describe('classifyStatus', () => {
  it.each([407, 511, 502, 503, 504])('is http for the proxy or filter status %d', (status) => {
    expect(classifyStatus(status)).toBe('http');
  });

  it.each([200, 204, 301, 401, 403, 404, 500])('is ok for status %d', (status) => {
    expect(classifyStatus(status)).toBe('ok');
  });

  it('is ok for a 404 on GET /: reaching the origin is the question, not what it served', () => {
    expect(classifyStatus(404)).toBe('ok');
  });
});

describe('cap', () => {
  it('leaves a blocker on a required endpoint alone', () => {
    expect(cap('blocker', true)).toBe('blocker');
  });

  it('caps a blocker on an optional endpoint at degraded', () => {
    expect(cap('blocker', false)).toBe('degraded');
  });

  it('never caps unknown: importance is orthogonal to "we could not tell"', () => {
    expect(cap('unknown', false)).toBe('unknown');
    expect(cap('unknown', true)).toBe('unknown');
  });

  it.each<Severity>(['degraded', 'ok'])('passes %s through on an optional endpoint', (severity) => {
    expect(cap(severity, false)).toBe(severity);
  });

  it.each<Severity>(['blocker', 'degraded', 'unknown', 'ok'])('passes %s through when required', (severity) => {
    expect(cap(severity, true)).toBe(severity);
  });
});
