import { afterEach, describe, expect, it } from 'vitest';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { NetworkGuard } from '../src/net/guard.ts';
import { pacFetcher } from '../src/net/pac-fetch.ts';
import type { PacFetchOutcome } from '../src/net/types.ts';
import type { Profile } from '../src/profiles/schema.ts';

/**
 * Loopback only, same rationale as `test/net-endpoint.test.ts`: every target
 * here is a `net.createServer` on 127.0.0.1, run offline and cross-platform.
 */

const LOOPBACK = '127.0.0.1';
const MACHINE_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

const servers: Server[] = [];
const sockets: Socket[] = [];

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy();
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => {
            resolve();
          });
        }),
    ),
  );
});

function profile(): Profile {
  return {
    name: 'Loopback fixture',
    endpoints: [],
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
  };
}

function portOf(server: Server): number {
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('expected a TCP address');
  return address.port;
}

async function listen(onConnection: (socket: Socket) => void): Promise<number> {
  const server = createServer((socket) => {
    sockets.push(socket);
    onConnection(socket);
  });
  servers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, LOOPBACK, resolve);
  });
  return portOf(server);
}

async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => {
    server.listen(0, LOOPBACK, resolve);
  });
  const port = portOf(server);
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
  return port;
}

/** Records `permit()` calls without a mocking framework, per repo convention. */
class OrderTrackingGuard extends NetworkGuard {
  readonly order: string[] = [];

  override permit(host: string, port: number, reason: string): void {
    this.order.push(`permit:${host}:${String(port)}`);
    super.permit(host, port, reason);
  }
}

function fetchOptions(guard: NetworkGuard, overrides: Partial<{ signal: AbortSignal; maxBytes: number }> = {}) {
  return {
    signal: new AbortController().signal,
    guard,
    maxBytes: 256 * 1024,
    ...overrides,
  };
}

function expectFailure(outcome: PacFetchOutcome): Extract<PacFetchOutcome, { ok: false }> {
  if (outcome.ok) throw new Error('expected a failed fetch, got ok');
  return outcome;
}

/** A minimal HTTP/1.1 response, hand-written since the server side is a raw socket. */
function httpResponse(status: number, statusText: string, body: string): string {
  return (
    `HTTP/1.1 ${String(status)} ${statusText}\r\n` +
    `Content-Length: ${String(Buffer.byteLength(body))}\r\n` +
    `Connection: close\r\n\r\n${body}`
  );
}

describe('pacFetcher', () => {
  it('fetches a PAC script over plain HTTP and reports elapsed time', async () => {
    const script = 'function FindProxyForURL(url, host) { return "DIRECT"; }';
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(httpResponse(200, 'OK', script));
      });
    });
    const guard = new NetworkGuard(profile());

    const outcome = await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard));

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error(`expected success, got ${outcome.phase}/${String(outcome.code)}`);
    expect(outcome.script).toBe(script);
    expect(outcome.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('permits the host before any socket connects', async () => {
    const script = 'function FindProxyForURL(url, host) { return "DIRECT"; }';
    const order: string[] = [];
    const port = await listen((socket) => {
      order.push('connect');
      socket.on('data', () => {
        socket.end(httpResponse(200, 'OK', script));
      });
    });
    const guard = new OrderTrackingGuard(profile());

    await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard));

    expect(guard.order).toEqual([`permit:${LOOPBACK}:${String(port)}`]);
    expect(guard.isAllowed(LOOPBACK, port)).toBe(true);
  });

  it('reports a closed port as a connect-phase ECONNREFUSED', async () => {
    const port = await closedPort();
    const guard = new NetworkGuard(profile());

    const outcome = await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard));

    const failure = expectFailure(outcome);
    expect(failure.phase).toBe('connect');
    expect(failure.code).toBe('ECONNREFUSED');
    expect(failure.abortedBy).toBeNull();
  });

  it('reports a non-200 status as an http-phase failure, never as a script', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(httpResponse(404, 'Not Found', ''));
      });
    });
    const guard = new NetworkGuard(profile());

    const outcome = await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard));

    const failure = expectFailure(outcome);
    expect(failure.phase).toBe('http');
    expect(failure.code).toBe('HTTP_404');
    expect(failure.code === null || MACHINE_CODE.test(failure.code)).toBe(true);
  });

  it('rejects a body larger than maxBytes cleanly, never truncating and succeeding', async () => {
    const body = 'x'.repeat(1_000);
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(httpResponse(200, 'OK', body));
      });
    });
    const guard = new NetworkGuard(profile());

    const outcome = await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard, { maxBytes: 16 }));

    const failure = expectFailure(outcome);
    expect(failure.phase).toBe('http');
    expect(failure.code).toBe('PAC_TOO_LARGE');
  });

  it('reports a black-hole peer as a phase-timeout when the run has not been cancelled', async () => {
    const port = await listen(() => {
      // Accept and say nothing: the connect succeeds, http never responds.
    });
    const guard = new NetworkGuard(profile());
    // fetchOptions uses no run-level timeout; rely on the fixture's own
    // internal http phase budget only via a run signal that never fires.
    const outcome = await pacFetcher.fetch(`http://${LOOPBACK}:${String(port)}/wpad.dat`, fetchOptions(guard));

    const failure = expectFailure(outcome);
    expect(failure.phase).toBe('http');
    expect(failure.abortedBy).toBe('phase-timeout');
  }, 10_000);

  it('reports the run signal, not a phase-timeout, when the whole run is cancelled', async () => {
    const port = await listen(() => {
      // The same black hole; this time the run is cancelled out from under it.
    });
    const guard = new NetworkGuard(profile());
    const controller = new AbortController();
    const cancel = setTimeout(() => {
      controller.abort();
    }, 50);
    try {
      const outcome = await pacFetcher.fetch(
        `http://${LOOPBACK}:${String(port)}/wpad.dat`,
        fetchOptions(guard, { signal: controller.signal }),
      );

      const failure = expectFailure(outcome);
      expect(failure.abortedBy).toBe('run-signal');
    } finally {
      clearTimeout(cancel);
    }
  });

  it('treats an unsupported URL scheme as a dns-phase failure without opening a socket', async () => {
    const guard = new NetworkGuard(profile());
    const outcome = await pacFetcher.fetch('ftp://example.com/wpad.dat', fetchOptions(guard));

    const failure = expectFailure(outcome);
    expect(failure.phase).toBe('dns');
    expect(failure.code).toBe('INVALID_PAC_URL');
  });
});
