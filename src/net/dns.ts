import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import type { NetworkGuard } from './guard.ts';
import type { DnsOutcome, DnsResolver } from './types.ts';

/**
 * Name resolution, at the I/O seam (ADR-0004).
 *
 * Two rules shape every line below, and neither is negotiable:
 *
 * 1. **The seam returns data, never an `Error`.** A resolver failure comes back
 *    as `{ ok: false, code }` so the classifier downstream stays a pure
 *    function over JSON-serialisable fixtures. The single exception is
 *    `NetworkPolicyError`: a caller resolving a host the profile never named is
 *    a bug in the caller, not a finding about the network, and must be loud.
 * 2. **No remote-controlled string leaves this file.** A DNS answer is
 *    attacker-influenced input. Only two shapes get out: an address that
 *    `net.isIP` accepts, and a `code` that matches `MACHINE_CODE`. Anything
 *    else becomes `null`, which the classifier reads as `unclassified` - never
 *    a wrong answer, unlike a leaked error message would be.
 *
 * `lookup` (getaddrinfo) rather than `resolve4`/`resolve6`: this seam answers
 * "what will the tool being deployed actually get?", and that is the system
 * resolver's answer, hosts file, search domains, NRPT rules and all. The DNS
 * probe that inspects the protocol directly is a separate concern (M2).
 */

/**
 * The shape of a Node/OpenSSL error code: uppercase, underscores, digits, and
 * short. This is the narrowing that keeps peer-controlled text out of the
 * report - a certificate subject or a resolver's error prose cannot survive it.
 */
const MACHINE_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

/** `err.code`, if it is a machine code; `null` for anything else. */
function codeOf(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || !('code' in value)) return null;
  const code = value.code;
  if (typeof code !== 'string' || !MACHINE_CODE.test(code)) return null;
  return code;
}

/**
 * The one code-shaped string this error carries, or `null`.
 *
 * `cause` and `AggregateError.errors` are checked because Node buries the
 * useful code there for TLS failures and for happy-eyeballs connect failures;
 * every candidate goes through the same `MACHINE_CODE` filter, so widening the
 * search does not widen what can escape.
 */
export function extractCode(error: unknown): string | null {
  const direct = codeOf(error);
  if (direct !== null) return direct;

  if (typeof error === 'object' && error !== null && 'cause' in error) {
    const fromCause = codeOf(error.cause);
    if (fromCause !== null) return fromCause;
  }

  if (error instanceof AggregateError) {
    for (const inner of error.errors) {
      const fromInner = codeOf(inner);
      if (fromInner !== null) return fromInner;
    }
  }

  return null;
}

/**
 * Which side of the composed signal fired. `AbortSignal.timeout` aborts with a
 * `TimeoutError`; an `AbortController` (the run deadline, Ctrl-C) aborts with
 * an `AbortError`. Callers that hold the run signal itself should prefer
 * checking `runSignal.aborted` - this is the fallback for a caller that was
 * handed one already-composed signal, as `resolve` is.
 */
function abortSourceOf(signal: AbortSignal): 'phase-timeout' | 'run-signal' {
  const reason: unknown = signal.reason;
  if (typeof reason === 'object' && reason !== null && 'name' in reason && reason.name === 'TimeoutError') {
    return 'phase-timeout';
  }
  return 'run-signal';
}

/**
 * Settle as soon as either `work` finishes or `signal` aborts.
 *
 * `dns.lookup` takes no `AbortSignal`, and a getaddrinfo call already handed to
 * the threadpool cannot be cancelled - so the abort abandons the answer rather
 * than stopping the work. `Promise.race` keeps a handler attached to `work`, so
 * a late rejection is still handled and never surfaces as an unhandled
 * rejection.
 */
async function raceAbort<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw new DnsAborted();

  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new DnsAborted());
    signal.addEventListener('abort', onAbort, { once: true });
  });

  try {
    return await Promise.race([work, aborted]);
  } finally {
    if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
  }
}

/** Internal marker: the phase signal fired. Never escapes this module. */
class DnsAborted extends Error {
  constructor() {
    super('resolution aborted');
    this.name = 'DnsAborted';
  }
}

function elapsedSince(startedAt: number): number {
  // `performance.now()` and not `Date.now()`: this number feeds the
  // slow-resolution check, and a clock step mid-run would fake a finding.
  return Math.round(performance.now() - startedAt);
}

export const systemResolver: DnsResolver = {
  async resolve(host: string, options: { signal: AbortSignal; guard: NetworkGuard }): Promise<DnsOutcome> {
    // First statement, before any resolver state exists: a host the profile did
    // not name is never looked up, not even to fail (SPEC.md 4.3).
    options.guard.assertHostAllowed(host);

    const startedAt = performance.now();
    try {
      const answers = await raceAbort(lookup(host, { all: true, verbatim: true }), options.signal);
      // The only remote-derived strings allowed out of this file, and only
      // after the OS-independent parser agrees they are IP addresses.
      const addresses = answers.map((answer) => answer.address).filter((address) => isIP(address) !== 0);
      return { ok: true, addresses, elapsedMs: elapsedSince(startedAt) };
    } catch (error) {
      if (options.signal.aborted) {
        return { ok: false, code: null, abortedBy: abortSourceOf(options.signal), elapsedMs: elapsedSince(startedAt) };
      }
      return { ok: false, code: extractCode(error), abortedBy: null, elapsedMs: elapsedSince(startedAt) };
    }
  },
};
