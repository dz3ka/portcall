import { afterEach, describe, expect, it } from 'vitest';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { NetworkGuard, NetworkPolicyError } from '../src/net/guard.ts';
import { systemResolver } from '../src/net/dns.ts';
import { endpointProber } from '../src/net/endpoint.ts';
import type { AttemptOptions, EndpointAttempt } from '../src/net/types.ts';
import type { Profile } from '../src/profiles/schema.ts';

/**
 * Loopback only. These tests run on Windows, macOS and Linux CI, so a case that
 * needs a name server or a route off the box is a flake, not a test: every
 * target here is a `net.createServer` on 127.0.0.1 (or a port that was just
 * closed), and every one of them is explicitly permitted so the guard is
 * exercised rather than bypassed.
 */

const LOOPBACK = '127.0.0.1';

/** A code the seam is allowed to surface: short, machine-shaped, never prose. */
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

/** Start a loopback listener and return its ephemeral port. */
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

/** A port that was bound just long enough to be sure nothing else holds it. */
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

function guardFor(port: number): NetworkGuard {
  const guard = new NetworkGuard(profile());
  guard.permit(LOOPBACK, port, 'test fixture');
  return guard;
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

function expectFailure(attempt: EndpointAttempt): Extract<EndpointAttempt, { ok: false }> {
  if (attempt.ok) throw new Error(`expected a failed attempt, got ok with status ${String(attempt.status)}`);
  return attempt;
}

describe('systemResolver', () => {
  it('resolves a loopback literal to itself and reports elapsed time', async () => {
    const guard = guardFor(443);
    const outcome = await systemResolver.resolve(LOOPBACK, { signal: new AbortController().signal, guard });

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error(`expected a resolved host, got code ${String(outcome.code)}`);
    expect(outcome.addresses).toContain(LOOPBACK);
    expect(outcome.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('refuses a host the profile never named, before resolving anything', async () => {
    const guard = new NetworkGuard(profile());
    await expect(
      systemResolver.resolve('never-named.example.com', { signal: new AbortController().signal, guard }),
    ).rejects.toBeInstanceOf(NetworkPolicyError);
  });
});

describe('endpointProber', () => {
  it('refuses a host:port the profile never named, before opening a socket', async () => {
    const guard = new NetworkGuard(profile());
    await expect(
      endpointProber.attempt({ host: 'never-named.example.com', port: 443, useTls: true }, attemptOptions(guard)),
    ).rejects.toBeInstanceOf(NetworkPolicyError);
  });

  it('refuses a permitted host on a port the profile never named', async () => {
    const guard = guardFor(443);
    await expect(
      endpointProber.attempt({ host: LOOPBACK, port: 9, useTls: false }, attemptOptions(guard)),
    ).rejects.toBeInstanceOf(NetworkPolicyError);
  });

  it('reports a closed port as a connect-phase ECONNREFUSED', async () => {
    const port = await closedPort();
    const attempt = await endpointProber.attempt(
      { host: LOOPBACK, port, useTls: false },
      attemptOptions(guardFor(port)),
    );

    const failure = expectFailure(attempt);
    expect(failure.phase).toBe('connect');
    expect(failure.code).toBe('ECONNREFUSED');
    expect(failure.abortedBy).toBeNull();
    expect(failure.addresses).toEqual([LOOPBACK]);
    expect(failure.timing.dnsMs).toBeGreaterThanOrEqual(0);
    expect(failure.timing.connectMs).toBeGreaterThanOrEqual(0);
    expect(failure.timing.tlsMs).toBeNull();
  });

  it('reports a peer that hangs up as a reset, with a machine-shaped code and no prose', async () => {
    // Windows reports ECONNRESET where Linux can report EPIPE for the same
    // hang-up, so the assertion is over the acceptable set, not one string.
    const port = await listen((socket) => {
      socket.destroy();
    });
    const attempt = await endpointProber.attempt(
      { host: LOOPBACK, port, useTls: true },
      attemptOptions(guardFor(port)),
    );

    const failure = expectFailure(attempt);
    expect(['connect', 'tls', 'http']).toContain(failure.phase);
    expect(['ECONNRESET', 'EPIPE']).toContain(failure.code);
    expect(failure.code === null || MACHINE_CODE.test(failure.code)).toBe(true);
    expect(failure.abortedBy).toBeNull();
  });

  it('reports a black-hole peer as a phase-timeout when the per-phase budget expires', async () => {
    const port = await listen(() => {
      // Accept and say nothing: the handshake never completes.
    });
    const attempt = await endpointProber.attempt(
      { host: LOOPBACK, port, useTls: true },
      attemptOptions(guardFor(port), { tlsTimeoutMs: 100 }),
    );

    const failure = expectFailure(attempt);
    expect(failure.phase).toBe('tls');
    expect(failure.abortedBy).toBe('phase-timeout');
    expect(failure.timing.connectMs).toBeGreaterThanOrEqual(0);
  });

  it('reports the run signal, not a phase-timeout, when the whole run is cancelled', async () => {
    const port = await listen(() => {
      // The same black hole; this time the run is cancelled out from under it.
    });
    const controller = new AbortController();
    const cancel = setTimeout(() => {
      controller.abort();
    }, 50);
    try {
      const attempt = await endpointProber.attempt(
        { host: LOOPBACK, port, useTls: true },
        attemptOptions(guardFor(port), { signal: controller.signal, tlsTimeoutMs: 30_000 }),
      );

      const failure = expectFailure(attempt);
      expect(failure.abortedBy).toBe('run-signal');
    } finally {
      clearTimeout(cancel);
    }
  });

  it('succeeds on a reachable non-HTTP port without sending a request', async () => {
    const received: Buffer[] = [];
    const port = await listen((socket) => {
      socket.on('data', (chunk: Buffer) => received.push(chunk));
    });
    const attempt = await endpointProber.attempt(
      { host: LOOPBACK, port, useTls: false },
      attemptOptions(guardFor(port)),
    );

    expect(attempt.ok).toBe(true);
    if (!attempt.ok) throw new Error(`expected a reachable endpoint, got ${attempt.phase}/${String(attempt.code)}`);
    expect(attempt.addresses).toEqual([LOOPBACK]);
    expect(attempt.tlsProtocol).toBeNull();
    expect(attempt.status).toBeNull();
    expect(attempt.timing.dnsMs).toBeGreaterThanOrEqual(0);
    expect(attempt.timing.connectMs).toBeGreaterThanOrEqual(0);
    expect(attempt.timing.tlsMs).toBeNull();
    expect(attempt.timing.httpMs).toBeNull();

    // A port that is neither 80 nor TLS is a plain reachability check: the seam
    // must not speak HTTP at something that never claimed to be HTTP.
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
    expect(received).toEqual([]);
  });
});
