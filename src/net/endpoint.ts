import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { connect as netConnect, isIP } from 'node:net';
import type { Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import type { ConnectionOptions, TLSSocket } from 'node:tls';
import { extractCode, systemResolver } from './dns.ts';
import type { AttemptOptions, AttemptPhase, AttemptTiming, EndpointAttempt, EndpointProber, EndpointTarget } from './types.ts';

/**
 * One endpoint attempt, phase by phase: dns -> connect -> tls -> http.
 *
 * The phases stay separate because the operational answer differs per phase:
 * "the name does not resolve", "the port is closed", "the handshake was
 * intercepted" and "the proxy returned 407" are four tickets for four teams
 * (CLAUDE.md). Collapsing them into "connection failed" would make the report
 * worthless in exactly the environment it exists for.
 *
 * Like `dns.ts`, this file returns data and never throws a network error - the
 * classifier downstream is a pure function over these records. `code` is only
 * ever a machine code from `extractCode`; a TLS error *message* embeds the
 * peer's certificate subject and altNames, and `text` evidence passes redaction
 * verbatim, so no message from this file reaches the caller. The one deliberate
 * throw is `NetworkPolicyError` from the guard: a caller aiming at a host the
 * profile never named is a bug, not a finding.
 */

/** The one port that means "plaintext HTTP" without a scheme to say so. */
const HTTP_PORT = 80;

/**
 * A socket error arriving after the phase that decided the outcome carries no
 * new information - but an unhandled `error` on a socket takes the process
 * down, and this tool runs once on a stranger's laptop. Every socket gets this
 * sink for its whole life; the phase logic listens separately.
 */
function ignore(): void {
  // Intentionally empty: see above.
}

function elapsedSince(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

export const endpointProber: EndpointProber = {
  async attempt(target: EndpointTarget, options: AttemptOptions): Promise<EndpointAttempt> {
    // First statement, before any socket object exists (SPEC.md 4.3).
    options.guard.assertAllowed(target.host, target.port);

    const timing: AttemptTiming = { dnsMs: null, connectMs: null, tlsMs: null, httpMs: null };
    let addresses: readonly string[] = [];
    let socket: Socket | undefined;
    let secure: TLSSocket | undefined;

    /**
     * Which half of the composed phase signal fired. The run signal is the
     * whole run's deadline or a Ctrl-C - "we ran out of time", not a verdict
     * about the network. The per-phase timer is a finding: this connect really
     * does hang. Reporting either as the other would turn a firewall drop into
     * a scheduling excuse, so the run signal is checked directly rather than
     * inferred from whatever error the socket happened to raise.
     */
    const abortSource = (): 'phase-timeout' | 'run-signal' => (options.signal.aborted ? 'run-signal' : 'phase-timeout');

    const phaseSignal = (budgetMs: number): AbortSignal =>
      AbortSignal.any([options.signal, AbortSignal.timeout(budgetMs)]);

    const failed = (phase: AttemptPhase, error: unknown, signal: AbortSignal): EndpointAttempt => {
      if (signal.aborted) {
        return { ok: false, phase, code: null, abortedBy: abortSource(), addresses, status: null, timing };
      }
      return { ok: false, phase, code: extractCode(error), abortedBy: null, addresses, status: null, timing };
    };

    try {
      // --- dns ------------------------------------------------------------
      // The DNS phase borrows the connect budget: `AttemptOptions` carries no
      // separate one, and an unbounded lookup against a black-hole resolver
      // would eat the whole run before a single socket opened.
      const dnsSignal = phaseSignal(options.connectTimeoutMs);
      const resolved = await systemResolver.resolve(target.host, { signal: dnsSignal, guard: options.guard });
      timing.dnsMs = resolved.elapsedMs;
      if (!resolved.ok) {
        const abortedBy = resolved.abortedBy === null ? null : abortSource();
        return { ok: false, phase: 'dns', code: resolved.code, abortedBy, addresses, status: null, timing };
      }
      addresses = resolved.addresses;

      // Only the first address is attempted. Reporting every address but
      // probing one keeps `connectMs` meaningful; a per-address sweep is a
      // separate finding ("resolves to N addresses, only M reachable") and not
      // this seam's job.
      const address = resolved.addresses[0];
      if (address === undefined) {
        return { ok: false, phase: 'dns', code: 'ENODATA', abortedBy: null, addresses, status: null, timing };
      }

      // --- connect --------------------------------------------------------
      const connectSignal = phaseSignal(options.connectTimeoutMs);
      const connectStartedAt = performance.now();
      socket = netConnect({ host: address, port: target.port });
      socket.on('error', ignore);
      try {
        await once(socket, 'connect', { signal: connectSignal });
      } catch (error) {
        timing.connectMs = elapsedSince(connectStartedAt);
        return failed('connect', error, connectSignal);
      }
      timing.connectMs = elapsedSince(connectStartedAt);

      // --- tls ------------------------------------------------------------
      let tlsProtocol: string | null = null;
      if (target.useTls) {
        const tlsSignal = phaseSignal(options.tlsTimeoutMs);
        const tlsStartedAt = performance.now();
        const tlsOptions: ConnectionOptions = { socket };
        // SNI carries a name, never a literal address: sending an IP in SNI is
        // malformed, and some middleboxes reject the handshake outright.
        if (isIP(target.host) === 0) tlsOptions.servername = target.host;
        // `rejectUnauthorized` stays at its default. An intercepting proxy's
        // certificate failing verification is the single most valuable finding
        // this tool produces; turning verification off would hide it.
        secure = tlsConnect(tlsOptions);
        secure.on('error', ignore);
        try {
          await once(secure, 'secureConnect', { signal: tlsSignal });
        } catch (error) {
          timing.tlsMs = elapsedSince(tlsStartedAt);
          return failed('tls', error, tlsSignal);
        }
        timing.tlsMs = elapsedSince(tlsStartedAt);
        tlsProtocol = secure.getProtocol();
      }

      // --- http -----------------------------------------------------------
      // Derived from the target, never from a schema field: TLS means HTTPS,
      // port 80 means plaintext HTTP, and any other bare port is a reachability
      // check only - speaking HTTP at a Postgres port would be noise at best.
      if (!target.useTls && target.port !== HTTP_PORT) {
        return { ok: true, addresses, tlsProtocol, status: null, timing };
      }

      const httpSignal = phaseSignal(options.httpTimeoutMs);
      const httpStartedAt = performance.now();
      let status: number | null;
      try {
        status = await requestStatus(secure ?? socket, target, httpSignal);
      } catch (error) {
        timing.httpMs = elapsedSince(httpStartedAt);
        return failed('http', error, httpSignal);
      }
      timing.httpMs = elapsedSince(httpStartedAt);

      return { ok: true, addresses, tlsProtocol, status, timing };
    } finally {
      // Every path closes the sockets it opened, including the success path:
      // the response body is never read, so there is nothing left to wait for.
      secure?.destroy();
      socket?.destroy();
    }
  },
};

/**
 * `GET /` over an already-connected socket, resolved with the status code only.
 *
 * Three deliberate omissions, each a requirement rather than a shortcut:
 * redirects are never followed (`Location` names a host the profile did not
 * declare, and `http.request` follows nothing on its own); no response header
 * is read (they are peer-controlled prose); and the body is never consumed -
 * the request is destroyed the moment the status line lands.
 */
function requestStatus(stream: Socket | TLSSocket, target: EndpointTarget, signal: AbortSignal): Promise<number | null> {
  return new Promise<number | null>((resolve, reject) => {
    const request = httpRequest({
      createConnection: () => stream,
      agent: false,
      host: target.host,
      port: target.port,
      path: '/',
      method: 'GET',
      headers: { connection: 'close' },
    });

    const onAbort = (): void => {
      request.destroy();
      reject(new Error('http phase aborted'));
    };

    request.on('error', (error: Error) => {
      signal.removeEventListener('abort', onAbort);
      reject(error);
    });

    request.on('response', (response: IncomingMessage) => {
      signal.removeEventListener('abort', onAbort);
      // The peer's only contribution that survives this function: a number,
      // and only if it is a plausible status code.
      const status = response.statusCode;
      const valid = typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599;
      response.destroy();
      request.destroy();
      resolve(valid ? status : null);
    });

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    request.end();
  });
}
