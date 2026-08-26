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

/**
 * The proxy seam (M2). `PacFetcher` fetches a PAC script over the same
 * phase-classified model as `EndpointAttempt`; `ProxyConnectAttempt` is the
 * outcome of one CONNECT attempt against a proxy, produced by
 * `connectDetailed` in `proxy-connect.ts` alongside the raw
 * `Proxy-Authenticate` header it never interprets (SPEC.md §4 — the probe
 * reports the scheme demanded and never authenticates).
 */
export type PacFetchOutcome =
  | { ok: true; script: string; elapsedMs: number }
  | {
      ok: false;
      phase: 'dns' | 'connect' | 'tls' | 'http';
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      elapsedMs: number;
    };

export interface PacFetcher {
  fetch(url: string, options: { signal: AbortSignal; guard: NetworkGuard; maxBytes: number }): Promise<PacFetchOutcome>;
}

export type AuthScheme = 'Basic' | 'NTLM' | 'Negotiate' | 'none' | 'unknown';

/**
 * No `authScheme` member: the scheme is not something this seam can know.
 * Classifying one means reading the raw `Proxy-Authenticate` header, which
 * travels on `ProxyConnectDetail` and is interpreted by
 * `probes/proxy/auth.ts` — the transport/judgment split every other seam in
 * this file keeps.
 */
export type ProxyConnectAttempt =
  | { ok: true; status: number; timing: AttemptTiming }
  | {
      ok: false;
      phase: AttemptPhase | 'tunnel';
      code: string | null;
      status: number | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      timing: AttemptTiming;
    };
