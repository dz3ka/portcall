import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import type { IncomingMessage } from 'node:http';
import { connect as netConnect, isIP } from 'node:net';
import type { Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import type { ConnectionOptions, TLSSocket } from 'node:tls';
import { extractCode, systemResolver } from './dns.ts';
import type { NetworkGuard } from './guard.ts';
import type { AttemptPhase, PacFetchOutcome, PacFetcher } from './types.ts';

/**
 * Fetches a PAC script, dns -> connect -> (tls) -> http, for both
 * `proxy.pac_url` and WPAD discovery (`http://wpad/wpad.dat`) - the same
 * phase-classified model as `endpoint.ts`, with one addition: the body IS
 * consumed here, because the point of a PAC fetch is the script text itself.
 * `endpoint.ts` deliberately never reads a body (see its module comment); this
 * file is the documented exception.
 *
 * Amendment A: `endpoint.ts`'s dns->connect portion is small (~20 lines of
 * phase logic) and each of the three PAC/proxy call sites has a genuinely
 * different post-connect step (TLS+GET-ignore-body / GET-capture-body /
 * CONNECT+read-one-header), so this file duplicates the dns/connect/tls
 * phase-sequencing pattern rather than extracting a shared helper. The
 * duplication is the phase-signal/abort-source plumbing only; the one real
 * piece of shared logic, `systemResolver.resolve`, is imported and reused.
 *
 * The PAC/WPAD host is never named in the profile, so it is admitted via
 * `guard.permit()` (not pre-permitted like a profile endpoint) before the
 * first guard-gated call - DNS resolution, which itself asserts host
 * allowance as its first statement (see `dns.ts`). The reason string is fixed
 * rather than built from the URL: a `pac_url` can carry a query string, and
 * `permit()`'s reason is disclosure text for the report, not evidence that
 * goes through redaction.
 *
 * `PacFetchOutcome`'s failure shape (`types.ts`) carries no `status` field -
 * unlike `EndpointAttempt`, this seam decides success/failure from the status
 * code itself rather than exposing it for a downstream classifier. A non-200
 * response is an `http`-phase failure with `code` set to `HTTP_<status>`, a
 * machine-shaped string in the same vein as `extractCode`'s node error codes.
 */

/** The one port that means "plaintext HTTP" without a scheme to say so. */
const HTTP_PORT = 80;
const HTTPS_PORT = 443;

/**
 * Fixed internal budgets: unlike `endpoint.ts`'s `AttemptOptions`, the
 * `PacFetcher.fetch` options bag carries only `signal` and `maxBytes` - a PAC
 * fetch is a one-off internal support call, not a profile-configurable
 * endpoint with its own budgets.
 */
const CONNECT_TIMEOUT_MS = 5_000;
const TLS_TIMEOUT_MS = 5_000;
const HTTP_TIMEOUT_MS = 5_000;

/** See `endpoint.ts`'s `ignore()`: every socket gets this sink for its whole life. */
function ignore(): void {
  // Intentionally empty: see above.
}

function elapsedSince(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

/** A response body that grew past the caller's cap. Never escapes this module as prose. */
class PacTooLarge extends Error {
  readonly code = 'PAC_TOO_LARGE';

  constructor() {
    super('PAC script exceeds the configured size cap');
    this.name = 'PacTooLarge';
  }
}

export const pacFetcher: PacFetcher = {
  async fetch(
    url: string,
    options: { signal: AbortSignal; guard: NetworkGuard; maxBytes: number },
  ): Promise<PacFetchOutcome> {
    const startedAt = performance.now();
    const elapsed = (): number => elapsedSince(startedAt);

    // See endpoint.ts:56-64 for why the run signal is checked directly rather
    // than inferred from whatever error the socket happened to raise.
    const abortSource = (): 'phase-timeout' | 'run-signal' => (options.signal.aborted ? 'run-signal' : 'phase-timeout');
    const phaseSignal = (budgetMs: number): AbortSignal => AbortSignal.any([options.signal, AbortSignal.timeout(budgetMs)]);
    const failed = (phase: AttemptPhase, error: unknown, signal: AbortSignal): PacFetchOutcome => {
      if (signal.aborted) {
        return { ok: false, phase, code: null, abortedBy: abortSource(), elapsedMs: elapsed() };
      }
      return { ok: false, phase, code: extractCode(error), abortedBy: null, elapsedMs: elapsed() };
    };

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      // No host was ever named, so this is treated as never having reached
      // the dns phase rather than invented as a fifth phase.
      return { ok: false, phase: 'dns', code: 'INVALID_PAC_URL', abortedBy: null, elapsedMs: elapsed() };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, phase: 'dns', code: 'INVALID_PAC_URL', abortedBy: null, elapsedMs: elapsed() };
    }

    const useTls = parsed.protocol === 'https:';
    const host = parsed.hostname;
    const port = parsed.port !== '' ? Number(parsed.port) : useTls ? HTTPS_PORT : HTTP_PORT;
    const path = `${parsed.pathname}${parsed.search}`;

    // Runtime-discovered host (SPEC.md 4.3): admitted explicitly, before any
    // guard-gated call - including the DNS resolution below, whose own first
    // statement is `guard.assertHostAllowed`.
    options.guard.permit(host, port, 'PAC script fetch');

    let socket: Socket | undefined;
    let secure: TLSSocket | undefined;

    try {
      // --- dns --------------------------------------------------------------
      const dnsSignal = phaseSignal(CONNECT_TIMEOUT_MS);
      const resolved = await systemResolver.resolve(host, { signal: dnsSignal, guard: options.guard });
      if (!resolved.ok) {
        const abortedBy = resolved.abortedBy === null ? null : abortSource();
        return { ok: false, phase: 'dns', code: resolved.code, abortedBy, elapsedMs: elapsed() };
      }
      const address = resolved.addresses[0];
      if (address === undefined) {
        return { ok: false, phase: 'dns', code: 'ENODATA', abortedBy: null, elapsedMs: elapsed() };
      }

      // --- connect ------------------------------------------------------------
      const connectSignal = phaseSignal(CONNECT_TIMEOUT_MS);
      socket = netConnect({ host: address, port });
      socket.on('error', ignore);
      try {
        await once(socket, 'connect', { signal: connectSignal });
      } catch (error) {
        return failed('connect', error, connectSignal);
      }

      // --- tls ------------------------------------------------------------
      if (useTls) {
        const tlsSignal = phaseSignal(TLS_TIMEOUT_MS);
        const tlsOptions: ConnectionOptions = { socket };
        if (isIP(host) === 0) tlsOptions.servername = host;
        secure = tlsConnect(tlsOptions);
        secure.on('error', ignore);
        try {
          await once(secure, 'secureConnect', { signal: tlsSignal });
        } catch (error) {
          return failed('tls', error, tlsSignal);
        }
      }

      // --- http -------------------------------------------------------------
      const httpSignal = phaseSignal(HTTP_TIMEOUT_MS);
      let response: { status: number | null; body: string };
      try {
        response = await fetchBody(secure ?? socket, { host, port, path }, options.maxBytes, httpSignal);
      } catch (error) {
        return failed('http', error, httpSignal);
      }

      if (response.status !== 200) {
        return {
          ok: false,
          phase: 'http',
          code: `HTTP_${response.status ?? 'UNKNOWN'}`,
          abortedBy: null,
          elapsedMs: elapsed(),
        };
      }

      return { ok: true, script: response.body, elapsedMs: elapsed() };
    } finally {
      secure?.destroy();
      socket?.destroy();
    }
  },
};

/**
 * `GET <path>` over an already-connected socket, resolved with the status
 * code and the body text - unlike `endpoint.ts`'s `requestStatus`, which
 * never reads the body at all. The size cap is enforced against bytes
 * actually received, never against a peer-supplied `Content-Length`: a
 * response that grows past `maxBytes` is destroyed and rejected, never
 * truncated and returned as if it were the whole script.
 */
function fetchBody(
  stream: Socket | TLSSocket,
  target: { host: string; port: number; path: string },
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ status: number | null; body: string }> {
  return new Promise<{ status: number | null; body: string }>((resolve, reject) => {
    const request = httpRequest({
      createConnection: () => stream,
      agent: false,
      host: target.host,
      port: target.port,
      path: target.path,
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
      const chunks: Buffer[] = [];
      let received = 0;
      let overflowed = false;

      response.on('data', (chunk: Buffer) => {
        if (overflowed) return;
        received += chunk.length;
        if (received > maxBytes) {
          overflowed = true;
          signal.removeEventListener('abort', onAbort);
          response.destroy();
          request.destroy();
          reject(new PacTooLarge());
          return;
        }
        chunks.push(chunk);
      });

      response.on('end', () => {
        if (overflowed) return;
        signal.removeEventListener('abort', onAbort);
        const status = response.statusCode;
        const valid = typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599;
        resolve({ status: valid ? status : null, body: Buffer.concat(chunks).toString('utf8') });
      });

      response.on('error', (error: Error) => {
        if (overflowed) return;
        signal.removeEventListener('abort', onAbort);
        reject(error);
      });
    });

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    request.end();
  });
}
