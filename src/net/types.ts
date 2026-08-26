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

/**
 * The TLS capture seam (M3, ADR-0002). Capture and validation are two jobs:
 * this seam opens the connection with certificate verification *deliberately
 * off* and hands back the presented chain as raw DER, and a pure function over
 * those bytes decides what the chain means. Nothing here interprets a
 * certificate, and nothing downstream reads a runtime certificate object -
 * that is what makes "the verdict is identical under Bun and Node" a testable
 * claim rather than a hope.
 *
 * `TunnelOutcome` is deliberately *not* here: it carries a live `net.Socket`,
 * and this file imports nothing from `node:*` so probes can depend on it
 * without tripping the networking-import guardrail. It lives beside the
 * function that produces it, in `proxy-connect.ts`.
 */
export interface TlsCaptureTiming {
  connectMs: number | null;
  tlsMs: number | null;
}

/**
 * A captured chain, or the phase it died in. The phases stay separate for the
 * same reason `EndpointAttempt`'s do (CLAUDE.md): a name that will not
 * resolve, a port that is closed, a proxy that answered the CONNECT itself and
 * a handshake that is being interfered with are four different tickets.
 *
 * `tunnel` is the one phase `EndpointAttempt` has no equivalent for, and it is
 * here for the reason ADR-0024 gives: a capture may run over a proxy tunnel,
 * and folding "the proxy refused" into `connect` hands the probe an `HTTP_407`
 * wearing a transport failure's phase - the commonest enterprise case, made
 * unrecognisable. There is no `http`: this seam never issues a request.
 *
 * Named rather than inline because the set is a vocabulary two other files
 * exhaust: the tls probe's per-phase verdict tables, and the evidence-kinds
 * guardrail, whose `Record<Union, true>` shape turns adding a phase here into
 * a typecheck failure there rather than a widened `text` vocabulary.
 */
export type TlsCapturePhase = 'dns' | 'connect' | 'tunnel' | 'tls';

export type TlsChainOutcome =
  | {
      ok: true;
      /** Leaf first, as presented, one DER-encoded certificate per element. */
      chainDer: readonly Uint8Array[];
      negotiatedProtocol: string | null;
      negotiatedCipher: string | null;
      /** The SNI actually sent; the empty string when the target was a literal address. */
      requestedSni: string;
      timing: TlsCaptureTiming;
    }
  | {
      ok: false;
      /** Chronological, so a reader can see how far the capture got. */
      phase: TlsCapturePhase;
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
    };

export interface TlsCaptureTarget {
  host: string;
  port: number;
  /** Present only when capturing through a proxy CONNECT tunnel; absent means direct. */
  viaProxy?: { host: string; port: number };
}

export interface TlsCaptureOptions {
  signal: AbortSignal;
  guard: NetworkGuard;
  connectTimeoutMs: number;
  tlsTimeoutMs: number;
}

export interface TlsCapture {
  capture(target: TlsCaptureTarget, options: TlsCaptureOptions): Promise<TlsChainOutcome>;
}
