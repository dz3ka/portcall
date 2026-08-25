import type { NetworkGuard } from './guard.ts';

/**
 * The network seam (M1). Probes depend on these interfaces, never on a socket
 * API: the real implementations live under `src/net/`, which is the only place
 * the guardrail test lets `node:net`/`node:tls`/`node:dns` be imported. This
 * file is types only and imports nothing from `node:*`, so a probe module can
 * import it without tripping that scan.
 *
 * The `guard` travels in the options bag on every call rather than being
 * captured by a factory. An implementation that closed over a guard could be
 * built once and reused after the guard changed; passing it per call makes the
 * enforcement point visible at the call site, where the host and port are.
 */

export type AttemptPhase = 'dns' | 'connect' | 'tls' | 'http';

/** Per-phase elapsed time; `null` for a phase that was never reached. */
export interface AttemptTiming {
  dnsMs: number | null;
  connectMs: number | null;
  tlsMs: number | null;
  httpMs: number | null;
}

/**
 * The outcome of one endpoint attempt. Failure carries the phase it died in:
 * DNS, connect-refused, TLS and HTTP are four different teams and four
 * different tickets (CLAUDE.md), so they are never collapsed into one error.
 */
export type EndpointAttempt =
  | { ok: true; addresses: readonly string[]; tlsProtocol: string | null; status: number | null; timing: AttemptTiming }
  | {
      ok: false;
      phase: AttemptPhase;
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      addresses: readonly string[];
      status: number | null;
      timing: AttemptTiming;
    };

export interface EndpointTarget {
  host: string;
  port: number;
  useTls: boolean;
}

export interface AttemptOptions {
  signal: AbortSignal;
  guard: NetworkGuard;
  connectTimeoutMs: number;
  tlsTimeoutMs: number;
  httpTimeoutMs: number;
}

export interface EndpointProber {
  attempt(target: EndpointTarget, options: AttemptOptions): Promise<EndpointAttempt>;
}

export type DnsOutcome =
  | { ok: true; addresses: readonly string[]; elapsedMs: number }
  | { ok: false; code: string | null; abortedBy: 'phase-timeout' | 'run-signal' | null; elapsedMs: number };

export interface DnsResolver {
  resolve(host: string, options: { signal: AbortSignal; guard: NetworkGuard }): Promise<DnsOutcome>;
}
