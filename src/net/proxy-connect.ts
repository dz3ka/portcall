import { once } from 'node:events';
import { Agent, request as httpRequest } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { connect as netConnect } from 'node:net';
import type { Socket } from 'node:net';
import { extractCode, systemResolver } from './dns.ts';
import type { AttemptOptions, AttemptPhase, AttemptTiming, ProxyConnectAttempt } from './types.ts';

/**
 * One proxy CONNECT attempt, dns -> connect -> tunnel: sends
 * `CONNECT <target-host>:<target-port> HTTP/1.1` to a proxy and reads exactly
 * one response (status line + headers). This is a detection probe, not a
 * working tunnel - on success the handed-back socket is destroyed
 * immediately, and no data is ever sent through it (SPEC.md 4, "the proxy
 * probe never authenticates").
 *
 * Structural non-negotiable: this file never constructs a request carrying an
 * `Authorization` request header of any kind, including the proxy-scoped
 * variant that RFC 7235 defines for a 407 challenge. The only headers sent
 * are `host` (the CONNECT target authority, required by RFC 7231 for CONNECT)
 * and `connection: close`. There is no code path - not even a disabled one -
 * that reads a credential or builds an auth header; `test/guardrails/
 * no-credential-access.test.ts` greps `src/` for the exact header names as a
 * trip-wire (this comment is deliberately worded to avoid tripping its own
 * scan - see that file for the literal patterns).
 *
 * The connection to the proxy itself is always plaintext TCP: this function
 * takes no `useTls` flag for the proxy hop, which matches the
 * standard forward-proxy model - the client connects to the proxy in the
 * clear, sends `CONNECT`, and only *after* a successful tunnel does TLS ever
 * happen, between the client and the origin, which this probe deliberately
 * never reaches. `AttemptPhase`'s `tls` member is therefore never produced by
 * this file; `AttemptOptions.tlsTimeoutMs` is accepted (the interface is
 * shared with `endpoint.ts`) but unused here.
 *
 * Amendment A (matching `pac-fetch.ts`'s decision, not re-litigating it):
 * `endpoint.ts`'s dns->connect phase logic is duplicated locally rather than
 * extracted, for the same reason - each call site's post-connect step differs
 * enough (GET-ignore-body / GET-capture-body / CONNECT+read-one-header) that
 * a shared helper would mostly be indirection. `systemResolver.resolve` is
 * reused, not reimplemented.
 *
 * Seam decision for the auth-scheme handoff: this module is pure I/O and
 * never classifies a scheme. `classifyAuthScheme` (`src/probes/proxy/auth.ts`)
 * is the judgment layer, mirroring `endpoint.ts`/`egress/classify.ts`'s
 * transport-vs-judgment split. `connectDetailed()` therefore returns the raw
 * `Proxy-Authenticate` header value on a separate field of
 * `ProxyConnectDetail`, beside the transport-only `ProxyConnectAttempt`; the
 * proxy probe classifies it and puts the scheme, never the header, in a
 * finding. An earlier revision also exported a `ProxyConnector`-shaped
 * wrapper that discarded that header; it was deleted once every caller needed
 * the header, along with the `authScheme` field on `ProxyConnectAttempt` that
 * only that wrapper's shape had asked for and that nothing could ever set.
 */

/** A socket error after the phase that decided the outcome carries no new information. */
function ignore(): void {
  // Intentionally empty: see endpoint.ts's `ignore()` for the full rationale.
}

function elapsedSince(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

interface TunnelResult {
  status: number | null;
  proxyAuthenticate: string | null;
}

/** The raw `Proxy-Authenticate` header value, unparsed and unclassified - see the module comment. */
export interface ProxyConnectDetail {
  attempt: ProxyConnectAttempt;
  proxyAuthenticate: string | null;
}

function firstHeaderValue(value: string | string[] | undefined): string | null {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}

/**
 * `CONNECT <authority> HTTP/1.1` over an already-connected socket, resolved
 * with the status and, on a non-2xx reply, the raw `Proxy-Authenticate`
 * header. Node's http module fires `'connect'` - never `'response'` - for
 * every reply to a CONNECT-method request, success or rejection alike; the
 * handed-back socket is destroyed immediately and never read from or written
 * to, on any status.
 *
 * The top-level `createConnection` option that `endpoint.ts`/`pac-fetch.ts`
 * pass alongside `agent: false` is honoured for ordinary methods but silently
 * ignored for `method: 'CONNECT'` (verified empirically against this Node
 * version - a request built that way tries to open its own connection to
 * `localhost:80` and fails with `ECONNREFUSED`). A one-shot `Agent` whose
 * `createConnection` returns the already-connected socket is the mechanism
 * Node's own CONNECT-tunnelling code path actually honours.
 */
function requestConnect(stream: Socket, target: { host: string; port: number }, signal: AbortSignal): Promise<TunnelResult> {
  return new Promise<TunnelResult>((resolve, reject) => {
    const authority = `${target.host}:${String(target.port)}`;
    const agent = new Agent({ keepAlive: false });
    agent.createConnection = () => stream;
    const request = httpRequest({
      agent,
      method: 'CONNECT',
      path: authority,
      headers: { host: authority, connection: 'close' },
    });

    const onAbort = (): void => {
      request.destroy();
      reject(new Error('tunnel phase aborted'));
    };

    request.on('error', (error: Error) => {
      signal.removeEventListener('abort', onAbort);
      reject(error);
    });

    // Fires for every reply to a CONNECT request, whatever the status. Never
    // read from or write to the handed-back socket - this is a detection
    // probe, not a working tunnel.
    request.on('connect', (response: IncomingMessage, socket: Socket) => {
      signal.removeEventListener('abort', onAbort);
      const status = response.statusCode;
      const valid = typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599;
      const proxyAuthenticate = valid && status !== 200 ? firstHeaderValue(response.headers['proxy-authenticate']) : null;
      socket.destroy();
      resolve({ status: valid ? status : null, proxyAuthenticate });
    });

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    request.end();
  });
}

/**
 * `ProxyConnectAttempt` plus the raw `Proxy-Authenticate` header - see the
 * module comment for the transport/judgment split that keeps the header out
 * of the attempt itself.
 */
export async function connectDetailed(
  proxy: { host: string; port: number },
  target: { host: string; port: number },
  options: AttemptOptions,
): Promise<ProxyConnectDetail> {
  const timing: AttemptTiming = { dnsMs: null, connectMs: null, tlsMs: null, httpMs: null };
  let socket: Socket | undefined;

  // Same reasoning as endpoint.ts/pac-fetch.ts: the run signal is the whole
  // run's deadline or Ctrl-C, the per-phase timer is a finding about this
  // proxy specifically.
  const abortSource = (): 'phase-timeout' | 'run-signal' => (options.signal.aborted ? 'run-signal' : 'phase-timeout');
  const phaseSignal = (budgetMs: number): AbortSignal => AbortSignal.any([options.signal, AbortSignal.timeout(budgetMs)]);
  const failed = (phase: AttemptPhase | 'tunnel', error: unknown, signal: AbortSignal): ProxyConnectDetail => {
    const attempt: ProxyConnectAttempt = signal.aborted
      ? { ok: false, phase, code: null, status: null, abortedBy: abortSource(), timing }
      : { ok: false, phase, code: extractCode(error), status: null, abortedBy: null, timing };
    return { attempt, proxyAuthenticate: null };
  };

  // Runtime-discovered host (SPEC.md 4.3): the proxy is never named in the
  // profile, so it is admitted via `guard.permit()` - mirrors
  // pac-fetch.ts's WPAD/PAC host handling - before the first guard-gated
  // call, DNS resolution, whose own first statement asserts host allowance.
  options.guard.permit(proxy.host, proxy.port, 'proxy CONNECT probe');

  try {
    // --- dns ------------------------------------------------------------
    const dnsSignal = phaseSignal(options.connectTimeoutMs);
    const resolved = await systemResolver.resolve(proxy.host, { signal: dnsSignal, guard: options.guard });
    timing.dnsMs = resolved.elapsedMs;
    if (!resolved.ok) {
      const abortedBy = resolved.abortedBy === null ? null : abortSource();
      return {
        attempt: { ok: false, phase: 'dns', code: resolved.code, status: null, abortedBy, timing },
        proxyAuthenticate: null,
      };
    }
    const address = resolved.addresses[0];
    if (address === undefined) {
      return {
        attempt: { ok: false, phase: 'dns', code: 'ENODATA', status: null, abortedBy: null, timing },
        proxyAuthenticate: null,
      };
    }

    // --- connect ----------------------------------------------------------
    const connectSignal = phaseSignal(options.connectTimeoutMs);
    const connectStartedAt = performance.now();
    socket = netConnect({ host: address, port: proxy.port });
    socket.on('error', ignore);
    try {
      await once(socket, 'connect', { signal: connectSignal });
    } catch (error) {
      timing.connectMs = elapsedSince(connectStartedAt);
      return failed('connect', error, connectSignal);
    }
    timing.connectMs = elapsedSince(connectStartedAt);

    // --- tunnel -------------------------------------------------------------
    // Reuses the http budget: a CONNECT round-trip is the closest analogue to
    // endpoint.ts's http phase, and AttemptOptions carries no separate one.
    const tunnelSignal = phaseSignal(options.httpTimeoutMs);
    const tunnelStartedAt = performance.now();
    let result: TunnelResult;
    try {
      result = await requestConnect(socket, target, tunnelSignal);
    } catch (error) {
      timing.httpMs = elapsedSince(tunnelStartedAt);
      return failed('tunnel', error, tunnelSignal);
    }
    timing.httpMs = elapsedSince(tunnelStartedAt);

    if (result.status === 200) {
      return { attempt: { ok: true, status: 200, timing }, proxyAuthenticate: null };
    }

    return {
      attempt: {
        ok: false,
        phase: 'tunnel',
        code: result.status === null ? null : `HTTP_${String(result.status)}`,
        status: result.status,
        abortedBy: null,
        timing,
      },
      proxyAuthenticate: result.proxyAuthenticate,
    };
  } finally {
    socket?.destroy();
  }
}
