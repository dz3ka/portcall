import { afterEach, describe, expect, it } from 'vitest';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { NetworkGuard } from '../src/net/guard.ts';
import { connectDetailed, openTunnel } from '../src/net/proxy-connect.ts';
import type { AttemptOptions, ProxyConnectAttempt } from '../src/net/types.ts';
import type { TunnelOutcome } from '../src/net/proxy-connect.ts';
import type { Profile } from '../src/profiles/schema.ts';

/**
 * Loopback only, same rationale as `test/net-endpoint.test.ts` and
 * `test/net-pac-fetch.test.ts`: every proxy here is a `net.createServer` on
 * 127.0.0.1, run offline and cross-platform. The `target` passed to
 * `connectDetailed` is never itself dialled - it is
 * only ever written into the CONNECT request line.
 */

const LOOPBACK = '127.0.0.1';
const TARGET = { host: 'origin.example.com', port: 443 };

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

function attemptOptions(guard: NetworkGuard, overrides: Partial<AttemptOptions> = {}): AttemptOptions {
  return {
    signal: new AbortController().signal,
    guard,
    connectTimeoutMs: 5_000,
    tlsTimeoutMs: 5_000,
    httpTimeoutMs: 5_000,
    ...overrides,
  };
}

function expectFailure(attempt: ProxyConnectAttempt): Extract<ProxyConnectAttempt, { ok: false }> {
  if (attempt.ok) throw new Error(`expected a failed attempt, got ok with status ${String(attempt.status)}`);
  return attempt;
}

/** A raw HTTP/1.1 response line + headers, hand-written since the server side is a raw socket. */
function rawResponse(status: number, statusText: string, headers: Record<string, string> = {}): string {
  const headerLines = Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}\r\n`)
    .join('');
  return `HTTP/1.1 ${String(status)} ${statusText}\r\n${headerLines}Connection: close\r\n\r\n`;
}

describe('connectDetailed', () => {
  it('reports an established tunnel on a 200 CONNECT reply', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(rawResponse(200, 'Connection Established'));
      });
    });
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    expect(detail.attempt.ok).toBe(true);
    if (!detail.attempt.ok) throw new Error(`expected success, got ${detail.attempt.phase}/${String(detail.attempt.code)}`);
    expect(detail.attempt.status).toBe(200);
    expect(detail.proxyAuthenticate).toBeNull();
  });

  it('permits the proxy host before any socket connects', async () => {
    const order: string[] = [];
    const port = await listen((socket) => {
      order.push('connect');
      socket.on('data', () => {
        socket.end(rawResponse(200, 'Connection Established'));
      });
    });
    const guard = new OrderTrackingGuard(profile());

    await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    expect(guard.order).toEqual([`permit:${LOOPBACK}:${String(port)}`]);
    expect(guard.isAllowed(LOOPBACK, port)).toBe(true);
  });

  it('captures a Basic Proxy-Authenticate challenge on a 407 without authenticating', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(rawResponse(407, 'Proxy Authentication Required', { 'Proxy-Authenticate': 'Basic realm="x"' }));
      });
    });
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    const failure = expectFailure(detail.attempt);
    expect(failure.phase).toBe('tunnel');
    expect(failure.status).toBe(407);
    // This seam never classifies a scheme: the raw header is handed back on
    // the separate `proxyAuthenticate` path, for the proxy probe to classify.
    expect(detail.proxyAuthenticate).toBe('Basic realm="x"');
  });

  it('captures an NTLM Proxy-Authenticate challenge on a 407', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(rawResponse(407, 'Proxy Authentication Required', { 'Proxy-Authenticate': 'NTLM' }));
      });
    });
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    expect(detail.proxyAuthenticate).toBe('NTLM');
  });

  it('captures a Negotiate Proxy-Authenticate challenge on a 407', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(rawResponse(407, 'Proxy Authentication Required', { 'Proxy-Authenticate': 'Negotiate' }));
      });
    });
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    expect(detail.proxyAuthenticate).toBe('Negotiate');
  });

  it('reports a closed proxy port as a connect-phase ECONNREFUSED', async () => {
    const port = await closedPort();
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    const failure = expectFailure(detail.attempt);
    expect(failure.phase).toBe('connect');
    expect(failure.code).toBe('ECONNREFUSED');
    expect(failure.abortedBy).toBeNull();
  });

  it('reports a reset mid-handshake as a tunnel-phase failure, not connect or dns', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.destroy();
      });
    });
    const guard = new NetworkGuard(profile());

    const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard));

    const failure = expectFailure(detail.attempt);
    expect(failure.phase).toBe('tunnel');
    // Windows reports ECONNRESET where other platforms can report EPIPE for
    // the same hang-up.
    expect(['ECONNRESET', 'EPIPE']).toContain(failure.code);
    expect(detail.proxyAuthenticate).toBeNull();
  });

  it('reports the run signal, not a phase-timeout, when the whole run is cancelled', async () => {
    const port = await listen(() => {
      // Accept and say nothing: the tunnel phase never gets a reply.
    });
    const guard = new NetworkGuard(profile());
    const controller = new AbortController();
    const cancel = setTimeout(() => {
      controller.abort();
    }, 50);
    try {
      const detail = await connectDetailed({ host: LOOPBACK, port }, TARGET, attemptOptions(guard, { signal: controller.signal }));

      const failure = expectFailure(detail.attempt);
      expect(failure.phase).toBe('tunnel');
      expect(failure.abortedBy).toBe('run-signal');
    } finally {
      clearTimeout(cancel);
    }
  });
});

/**
 * `openTunnel` is the same CONNECT exchange as `connectDetailed`, with the
 * opposite ending: the socket survives, because the TLS capture (M3) has to
 * hand a real tunnel to a real handshake. The tests below therefore care about
 * two things `connectDetailed`'s do not - that a successful tunnel is still
 * writable, and that every unsuccessful one closes what it opened.
 */

function expectTunnelFailure(outcome: TunnelOutcome): Extract<TunnelOutcome, { ok: false }> {
  if (outcome.ok) {
    outcome.socket.destroy();
    throw new Error('expected the tunnel to fail');
  }
  return outcome;
}

function tunnelOptions(guard: NetworkGuard, overrides: Partial<{ signal: AbortSignal; connectTimeoutMs: number }> = {}) {
  return { signal: new AbortController().signal, guard, connectTimeoutMs: 5_000, ...overrides };
}

describe('openTunnel', () => {
  it('hands back a live socket after a 200, and the caller can still speak over it', async () => {
    const received: Buffer[] = [];
    const port = await listen((socket) => {
      socket.on('data', (chunk: Buffer) => {
        if (received.length === 0) {
          received.push(chunk);
          socket.write(rawResponse(200, 'Connection Established'));
          return;
        }
        // Post-tunnel bytes: echo them back, the way an origin server would.
        socket.write(chunk);
      });
    });
    const guard = new NetworkGuard(profile());

    const outcome = await openTunnel({ host: LOOPBACK, port }, TARGET, tunnelOptions(guard));

    if (!outcome.ok) throw new Error(`expected a tunnel, got ${outcome.phase}/${String(outcome.code)}`);
    try {
      expect(outcome.socket.destroyed).toBe(false);
      const echoed = new Promise<Buffer>((resolve) => {
        outcome.socket.once('data', resolve);
      });
      outcome.socket.write('hello-through-the-tunnel');
      expect((await echoed).toString('utf8')).toBe('hello-through-the-tunnel');
    } finally {
      // Ownership transfers with the socket: see openTunnel's doc comment.
      outcome.socket.destroy();
    }
    expect(guard.isAllowed(LOOPBACK, port)).toBe(true);
  });

  it('never sends an auth header, even when the proxy was given with credentials in its URL', async () => {
    const received: string[] = [];
    const port = await listen((socket) => {
      socket.on('data', (chunk: Buffer) => {
        received.push(chunk.toString('utf8'));
        socket.end(rawResponse(200, 'Connection Established'));
      });
    });
    // The shape an operator's environment actually carries: `HTTPS_PROXY`
    // with userinfo embedded. `openTunnel` takes a host and a port and has no
    // parameter a credential could travel in, so the userinfo cannot reach the
    // wire - this test pins that at run time, beside the static grep in
    // `test/guardrails/no-credential-access.test.ts`.
    const configured = new URL(`http://portcall-probe:hunter2@${LOOPBACK}:${String(port)}`);
    const guard = new NetworkGuard(profile());

    const outcome = await openTunnel(
      { host: configured.hostname, port: Number(configured.port) },
      TARGET,
      tunnelOptions(guard),
    );
    if (outcome.ok) outcome.socket.destroy();

    const wire = received.join('');
    expect(wire).toContain(`CONNECT ${TARGET.host}:${String(TARGET.port)} HTTP/1.1`);
    expect(wire).not.toMatch(/authori[sz]ation/i);
    expect(wire).not.toContain('hunter2');
    expect(wire).not.toContain('portcall-probe');
    // Neither in the clear nor encoded the way a Basic credential would be.
    expect(wire).not.toContain(Buffer.from('portcall-probe:hunter2', 'utf8').toString('base64'));
  });

  it('closes the socket it opened when the proxy rejects the tunnel', async () => {
    let closed: Promise<void> | undefined;
    const port = await listen((socket) => {
      closed = new Promise<void>((resolve) => {
        socket.on('close', () => {
          resolve();
        });
      });
      socket.on('data', () => {
        socket.write(rawResponse(407, 'Proxy Authentication Required', { 'Proxy-Authenticate': 'NTLM' }));
      });
    });
    const guard = new NetworkGuard(profile());

    const failure = expectTunnelFailure(await openTunnel({ host: LOOPBACK, port }, TARGET, tunnelOptions(guard)));

    expect(failure.phase).toBe('tunnel');
    expect(failure.status).toBe(407);
    expect(failure.code).toBe('HTTP_407');
    // No leak: the proxy side sees the connection go away without the caller
    // ever having been handed a socket to close.
    await closed;
  });

  it('reports a closed proxy port as a connect-phase ECONNREFUSED', async () => {
    const port = await closedPort();
    const guard = new NetworkGuard(profile());

    const failure = expectTunnelFailure(await openTunnel({ host: LOOPBACK, port }, TARGET, tunnelOptions(guard)));

    expect(failure.phase).toBe('connect');
    expect(failure.code).toBe('ECONNREFUSED');
    expect(failure.status).toBeNull();
  });

  it('reports the run signal when the whole run is cancelled mid-tunnel', async () => {
    const port = await listen(() => {
      // Accept and stay silent: the CONNECT reply never arrives.
    });
    const guard = new NetworkGuard(profile());
    const controller = new AbortController();
    const cancel = setTimeout(() => {
      controller.abort();
    }, 50);
    try {
      const failure = expectTunnelFailure(
        await openTunnel({ host: LOOPBACK, port }, TARGET, tunnelOptions(guard, { signal: controller.signal })),
      );

      expect(failure.phase).toBe('tunnel');
      expect(failure.abortedBy).toBe('run-signal');
    } finally {
      clearTimeout(cancel);
    }
  });

  it('permits the proxy host before any socket connects', async () => {
    const port = await listen((socket) => {
      socket.on('data', () => {
        socket.end(rawResponse(200, 'Connection Established'));
      });
    });
    const guard = new OrderTrackingGuard(profile());

    const outcome = await openTunnel({ host: LOOPBACK, port }, TARGET, tunnelOptions(guard));
    if (outcome.ok) outcome.socket.destroy();

    expect(guard.order).toEqual([`permit:${LOOPBACK}:${String(port)}`]);
  });
});
