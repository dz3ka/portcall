import { once } from 'node:events';
import { connect as netConnect, isIP } from 'node:net';
import type { Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import type { ConnectionOptions, DetailedPeerCertificate, TLSSocket } from 'node:tls';
import { extractCode, systemResolver } from './dns.ts';
import { openTunnel } from './proxy-connect.ts';
import type { TlsCapture, TlsCaptureOptions, TlsCaptureTarget, TlsCaptureTiming, TlsChainOutcome } from './types.ts';

/**
 * The capture half of ADR-0002: open a TLS connection, take the chain the peer
 * presented as raw DER, note the protocol and cipher that were negotiated, and
 * stop. Nothing in this file decides whether a certificate is valid, expired,
 * public, private, or a match for the name it was asked for - that is a pure
 * function over these bytes, and it lives in the probe.
 *
 * **Verification is deliberately off, and that is the probe.** `tls.connect`
 * is called with `rejectUnauthorized: false` on purpose. A verifying client
 * facing a corporate interception proxy gets `SELF_SIGNED_CERT_IN_CHAIN` and
 * *no chain to look at* - which is precisely the useless error this tool
 * exists to replace (SPEC.md 7). Turning verification off is what lets the
 * intercepted, expired or mis-issued chain be observed and reported instead of
 * thrown away. Three things keep that from being a security hole:
 *
 * - not one byte of application data is ever written to the connection: the
 *   handshake completes, the chain is copied out, the socket is destroyed;
 * - the trust decision is not skipped, it is *moved* - downstream, in a pure
 *   function, where its inputs and its reasoning are both fixture-testable;
 * - `NetworkGuard` still gates the connection, so a chain can only be captured
 *   from a host the active profile named.
 *
 * Duplication note, same as `proxy-connect.ts`'s Amendment A: the dns->connect
 * sequence is written out here rather than shared with `endpoint.ts`, because
 * what follows the connect (upgrade and capture, versus GET-and-read-status)
 * is where all the substance is. `systemResolver.resolve` is reused.
 */

/**
 * Re-exported at the seam that produces them so a caller can import the
 * function and its result type from one place; the definitions live in
 * `types.ts`, which imports nothing from `node:*` and so can be depended on by
 * a probe without tripping the networking-import guardrail.
 */
export type { TlsCapture, TlsCaptureOptions, TlsCaptureTarget, TlsChainOutcome } from './types.ts';

/** See `endpoint.ts`'s `ignore()`: an unhandled socket `error` would take the process down. */
function ignore(): void {
  // Intentionally empty.
}

function elapsedSince(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

/**
 * The presented chain, leaf first, as DER.
 *
 * Node models the chain as a linked list through `issuerCertificate`, and
 * terminates it by pointing the last certificate at *itself* - so the walk
 * stops on a fingerprint it has already seen, which also makes a peer that
 * sends a genuine loop harmless. `getPeerCertificate(true)` returns `{}` (no
 * `raw`) when there is no peer certificate at all, hence the `Uint8Array`
 * check rather than a truthiness test.
 *
 * Each `raw` Buffer is copied into a standalone `Uint8Array`. Buffers come
 * from a shared pool; handing that memory to a probe that keeps it for the
 * length of a report is how a subtle aliasing bug gets written, and the DER of
 * a certificate chain is a few kilobytes.
 */
function chainDerOf(secure: TLSSocket): readonly Uint8Array[] {
  const chain: Uint8Array[] = [];
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = secure.getPeerCertificate(true);

  while (current !== undefined && current.raw instanceof Uint8Array && !seen.has(current.fingerprint256)) {
    seen.add(current.fingerprint256);
    chain.push(new Uint8Array(current.raw));
    current = current.issuerCertificate;
  }
  return chain;
}

export const tlsCapturer: TlsCapture = {
  async capture(target: TlsCaptureTarget, options: TlsCaptureOptions): Promise<TlsChainOutcome> {
    // First statement, before any socket object exists (SPEC.md 4.3). The
    // capture target is a profile-declared host, so it is asserted rather than
    // permitted; the proxy in `viaProxy` is the runtime-discovered one, and
    // `openTunnel` admits it with a reason.
    options.guard.assertAllowed(target.host, target.port);

    const timing: TlsCaptureTiming = { connectMs: null, tlsMs: null };
    let socket: Socket | undefined;
    let secure: TLSSocket | undefined;

    // Which half of a composed phase signal fired, kept apart for the same
    // reason `endpoint.ts` keeps them apart: "the run ran out of time" is not a
    // finding about this network, and "this handshake hangs" is.
    const abortSource = (): 'phase-timeout' | 'run-signal' => (options.signal.aborted ? 'run-signal' : 'phase-timeout');
    const phaseSignal = (budgetMs: number): AbortSignal => AbortSignal.any([options.signal, AbortSignal.timeout(budgetMs)]);
    const failed = (phase: 'dns' | 'connect' | 'tls', error: unknown, signal: AbortSignal): TlsChainOutcome =>
      signal.aborted
        ? { ok: false, phase, code: null, abortedBy: abortSource() }
        : { ok: false, phase, code: extractCode(error), abortedBy: null };

    try {
      // --- transport: a proxy tunnel, or a direct connection ----------------
      const transportStartedAt = performance.now();
      if (target.viaProxy !== undefined) {
        // The tunnel's own dns and connect phases are inside `openTunnel`;
        // `connectMs` covers the whole leg, which is what an operator reading
        // "time to reach the origin through the proxy" means by it.
        const tunnel = await openTunnel(
          target.viaProxy,
          { host: target.host, port: target.port },
          { signal: options.signal, guard: options.guard, connectTimeoutMs: options.connectTimeoutMs },
        );
        timing.connectMs = elapsedSince(transportStartedAt);
        if (!tunnel.ok) {
          // The tunnel's phases are the capture's phases (ADR-0024).
          return { ok: false, phase: tunnel.phase, code: tunnel.code, abortedBy: tunnel.abortedBy };
        }
        // Ownership passes here: the `finally` below closes it, on every path.
        socket = tunnel.socket;
      } else {
        // --- dns ----------------------------------------------------------
        const dnsSignal = phaseSignal(options.connectTimeoutMs);
        const resolved = await systemResolver.resolve(target.host, { signal: dnsSignal, guard: options.guard });
        if (!resolved.ok) {
          const abortedBy = resolved.abortedBy === null ? null : abortSource();
          return { ok: false, phase: 'dns', code: resolved.code, abortedBy };
        }
        const address = resolved.addresses[0];
        if (address === undefined) {
          return { ok: false, phase: 'dns', code: 'ENODATA', abortedBy: null };
        }

        // --- connect ------------------------------------------------------
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
      }

      // --- tls ------------------------------------------------------------
      const tlsSignal = phaseSignal(options.tlsTimeoutMs);
      const tlsStartedAt = performance.now();
      // SNI carries a name, never a literal address: sending an IP in SNI is
      // malformed, and some middleboxes reject the handshake outright. What
      // was asked for is reported, because "which name did we ask for" is half
      // of "does the certificate match the name" downstream.
      const requestedSni = isIP(target.host) === 0 ? target.host : '';
      const tlsOptions: ConnectionOptions = { socket, rejectUnauthorized: false };
      if (requestedSni !== '') tlsOptions.servername = requestedSni;

      secure = tlsConnect(tlsOptions);
      secure.on('error', ignore);
      try {
        await once(secure, 'secureConnect', { signal: tlsSignal });
      } catch (error) {
        timing.tlsMs = elapsedSince(tlsStartedAt);
        return failed('tls', error, tlsSignal);
      }
      timing.tlsMs = elapsedSince(tlsStartedAt);

      // `standardName` is the IANA cipher name and is what a reader can look
      // up; `name` is OpenSSL's spelling of the same suite, kept as the
      // fallback for a runtime that does not fill the former in.
      const cipher = secure.getCipher();

      return {
        ok: true,
        chainDer: chainDerOf(secure),
        negotiatedProtocol: secure.getProtocol(),
        negotiatedCipher: cipher.standardName ?? cipher.name,
        requestedSni,
        timing,
      };
    } finally {
      // Every path closes both sockets, success included - the chain has been
      // copied out by then, and nothing else was ever going to be sent.
      secure?.destroy();
      socket?.destroy();
    }
  },
};
