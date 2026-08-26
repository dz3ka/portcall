import { afterEach, describe, expect, it } from 'vitest';
import { lookup } from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { connect as netConnect, createServer as createNetServer } from 'node:net';
import type { Server as NetServer, Socket } from 'node:net';
import { join } from 'node:path';
import { createServer as createTlsServer } from 'node:tls';
import type { Server as TlsServer } from 'node:tls';
import { NetworkGuard } from '../src/net/guard.ts';
import { tlsCapturer } from '../src/net/tls-capture.ts';
import type { TlsCaptureTarget, TlsChainOutcome } from '../src/net/types.ts';
import type { Profile } from '../src/profiles/schema.ts';

/**
 * In-process only, same rationale as `test/net-endpoint.test.ts`: every server
 * here listens on loopback, so the suite runs offline, on every CI OS, with no
 * egress at all.
 *
 * The fixture chain (`test/fixtures/tls/`) is a leaf signed by a throwaway
 * private root, which is exactly the shape a corporate interception proxy
 * presents. Capturing it *successfully* — rather than failing the handshake —
 * is the property ADR-0002 and SPEC.md §7 rest on: the probe observes the
 * chain it deliberately does not trust, and the judgment about what that chain
 * means happens later, in a pure function over these DER bytes.
 */

const FIXTURE_DIR = join(import.meta.dirname, 'fixtures', 'tls');
const LEAF_KEY = readFileSync(join(FIXTURE_DIR, 'leaf.key.pem'));
const LEAF_CERT = readFileSync(join(FIXTURE_DIR, 'leaf.cert.pem'), 'utf8');
const ROOT_CERT = readFileSync(join(FIXTURE_DIR, 'ca.cert.pem'), 'utf8');

const LOOPBACK = '127.0.0.1';

const netServers: NetServer[] = [];
const tlsServers: TlsServer[] = [];
const sockets: Socket[] = [];

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy();
  const closing = [...netServers.splice(0), ...tlsServers.splice(0)].map(
    (server) =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      }),
  );
  await Promise.all(closing);
});

function profile(endpoints: Profile['endpoints']): Profile {
  return {
    name: 'Loopback fixture',
    endpoints,
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
  };
}

function endpoint(host: string, port: number): Profile['endpoints'][number] {
  return { host, port, purpose: 'fixture', required: true, expect_streaming: false };
}

function portOf(server: NetServer | TlsServer): number {
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('expected a TCP address');
  return address.port;
}

/**
 * The address `localhost` actually resolves to *here*, asked for exactly the
 * way `net/dns.ts` asks (getaddrinfo, verbatim order). Binding the fixture
 * server to that address keeps the `localhost` tests deterministic on a
 * machine whose loopback answer is `::1` as well as one whose answer is
 * `127.0.0.1` — the capture dials whichever the OS names first.
 */
async function localhostAddress(): Promise<string> {
  const answers = await lookup('localhost', { all: true, verbatim: true });
  const first = answers[0];
  if (first === undefined) throw new Error('localhost does not resolve on this machine');
  return first.address;
}

/** A TLS server presenting the fixture leaf plus its private root, chain order leaf-first. */
async function listenTls(bindAddress: string): Promise<number> {
  const server = createTlsServer({ key: LEAF_KEY, cert: `${LEAF_CERT}\n${ROOT_CERT}` }, (socket) => {
    // Never speak first and never read: this end exists to complete a
    // handshake, nothing more.
    socket.on('error', () => {
      /* the client destroys the connection the moment it has the chain */
    });
  });
  tlsServers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, bindAddress, resolve);
  });
  return portOf(server);
}

/** A plain TCP listener that accepts and then says nothing, so the TLS phase hangs. */
async function listenSilent(): Promise<number> {
  const server = createNetServer((socket) => {
    sockets.push(socket);
  });
  netServers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, LOOPBACK, resolve);
  });
  return portOf(server);
}

async function closedPort(): Promise<number> {
  const server = createNetServer();
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

/**
 * A minimal forward proxy: answers any CONNECT with 200 and then pipes bytes
 * both ways. It never inspects the tunnelled stream — it only has to prove
 * that `openTunnel` hands back a socket a TLS handshake can still run over.
 */
async function listenProxy(origin: { host: string; port: number }): Promise<number> {
  const server = createNetServer((client) => {
    sockets.push(client);
    client.once('data', () => {
      const upstream = netConnect({ host: origin.host, port: origin.port }, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        client.pipe(upstream);
        upstream.pipe(client);
      });
      sockets.push(upstream);
      upstream.on('error', () => {
        client.destroy();
      });
    });
    client.on('error', () => {
      /* the capture destroys the tunnel as soon as it has the chain */
    });
  });
  netServers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, LOOPBACK, resolve);
  });
  return portOf(server);
}

/**
 * A proxy that answers every CONNECT itself instead of tunnelling — a policy
 * denial or an auth challenge, which are the two ways an enterprise proxy says
 * no, and the two the capture has to report as the same phase.
 */
async function listenRefusingProxy(response: string): Promise<number> {
  const server = createNetServer((socket) => {
    sockets.push(socket);
    socket.on('data', () => {
      socket.end(response);
    });
  });
  netServers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, LOOPBACK, resolve);
  });
  return portOf(server);
}

function captureOptions(guard: NetworkGuard, overrides: Partial<{ signal: AbortSignal; connectTimeoutMs: number; tlsTimeoutMs: number }> = {}) {
  return {
    signal: new AbortController().signal,
    guard,
    connectTimeoutMs: 5_000,
    tlsTimeoutMs: 5_000,
    ...overrides,
  };
}

function expectFailure(outcome: TlsChainOutcome): Extract<TlsChainOutcome, { ok: false }> {
  if (outcome.ok) throw new Error(`expected a failed capture, got a chain of ${String(outcome.chainDer.length)}`);
  return outcome;
}

function expectSuccess(outcome: TlsChainOutcome): Extract<TlsChainOutcome, { ok: true }> {
  if (!outcome.ok) throw new Error(`expected a captured chain, got ${outcome.phase}/${String(outcome.code)}`);
  return outcome;
}

describe('tlsCapturer', () => {
  it('captures a privately-rooted chain instead of rejecting it', async () => {
    const address = await localhostAddress();
    const port = await listenTls(address);
    const guard = new NetworkGuard(profile([endpoint('localhost', port)]));
    const target: TlsCaptureTarget = { host: 'localhost', port };

    const outcome = expectSuccess(await tlsCapturer.capture(target, captureOptions(guard)));

    // Leaf first, then the private root the server sent alongside it. A
    // verifying client would have failed this handshake outright; this one
    // deliberately does not, which is the whole point of the probe.
    expect(outcome.chainDer).toHaveLength(2);
    for (const der of outcome.chainDer) {
      expect(der).toBeInstanceOf(Uint8Array);
      // Every DER certificate starts with a SEQUENCE tag.
      expect(der[0]).toBe(0x30);
      expect(der.byteLength).toBeGreaterThan(200);
    }
    expect(outcome.chainDer[0]).not.toEqual(outcome.chainDer[1]);
  });

  it('reports the negotiated protocol, cipher and the SNI it asked for', async () => {
    const address = await localhostAddress();
    const port = await listenTls(address);
    const guard = new NetworkGuard(profile([endpoint('localhost', port)]));

    const outcome = expectSuccess(await tlsCapturer.capture({ host: 'localhost', port }, captureOptions(guard)));

    expect(outcome.negotiatedProtocol).toMatch(/^TLSv1\.[23]$/);
    expect(outcome.negotiatedCipher).toBeTruthy();
    expect(outcome.requestedSni).toBe('localhost');
    expect(outcome.timing.connectMs).toBeGreaterThanOrEqual(0);
    expect(outcome.timing.tlsMs).toBeGreaterThanOrEqual(0);
  });

  it('sends no SNI for a literal address, and says so with an empty requestedSni', async () => {
    const port = await listenTls(LOOPBACK);
    const guard = new NetworkGuard(profile([endpoint('example.test', 443)]));
    guard.permit(LOOPBACK, port, 'fixture');

    const outcome = expectSuccess(await tlsCapturer.capture({ host: LOOPBACK, port }, captureOptions(guard)));

    expect(outcome.requestedSni).toBe('');
    expect(outcome.chainDer).toHaveLength(2);
  });

  it('captures the same chain through a proxy CONNECT tunnel', async () => {
    const address = await localhostAddress();
    const originPort = await listenTls(address);
    const proxyPort = await listenProxy({ host: address, port: originPort });
    const guard = new NetworkGuard(profile([endpoint('localhost', originPort)]));

    const outcome = expectSuccess(
      await tlsCapturer.capture(
        { host: 'localhost', port: originPort, viaProxy: { host: LOOPBACK, port: proxyPort } },
        captureOptions(guard),
      ),
    );

    expect(outcome.chainDer).toHaveLength(2);
    expect(outcome.requestedSni).toBe('localhost');
    // The proxy was never named in the profile: the tunnel admitted it.
    expect(guard.isAllowed(LOOPBACK, proxyPort)).toBe(true);
  });

  it('reports a proxy that refuses the tunnel as a tunnel-phase failure carrying the status code', async () => {
    const address = await localhostAddress();
    const originPort = await listenTls(address);
    const rejectingProxy = await listenRefusingProxy('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    const guard = new NetworkGuard(profile([endpoint('localhost', originPort)]));

    const failure = expectFailure(
      await tlsCapturer.capture(
        { host: 'localhost', port: originPort, viaProxy: { host: LOOPBACK, port: rejectingProxy } },
        captureOptions(guard),
      ),
    );

    // ADR-0024: not `connect`. A proxy that answered the CONNECT itself is a
    // different ticket from a proxy that never opened a socket, and the probe
    // branches on the phase rather than sniffing the code string.
    expect(failure.phase).toBe('tunnel');
    expect(failure.code).toBe('HTTP_403');
  });

  it('reports a proxy demanding authentication as the same tunnel phase, code HTTP_407', async () => {
    const address = await localhostAddress();
    const originPort = await listenTls(address);
    const authProxy = await listenRefusingProxy(
      'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="corp"\r\nConnection: close\r\n\r\n',
    );
    const guard = new NetworkGuard(profile([endpoint('localhost', originPort)]));

    const failure = expectFailure(
      await tlsCapturer.capture(
        { host: 'localhost', port: originPort, viaProxy: { host: LOOPBACK, port: authProxy } },
        captureOptions(guard),
      ),
    );

    // The commonest enterprise case, and the one the collapsed phase handed the
    // probe as an unrecognisable `connect`/`HTTP_407` pair. Nothing here
    // authenticates: the challenge is observed and the capture stops.
    expect(failure.phase).toBe('tunnel');
    expect(failure.code).toBe('HTTP_407');
    expect(failure.abortedBy).toBeNull();
  });

  it('reports a closed port as a connect-phase ECONNREFUSED, not a TLS failure', async () => {
    const port = await closedPort();
    const guard = new NetworkGuard(profile([endpoint('example.test', 443)]));
    guard.permit(LOOPBACK, port, 'fixture');

    const failure = expectFailure(await tlsCapturer.capture({ host: LOOPBACK, port }, captureOptions(guard)));

    expect(failure.phase).toBe('connect');
    expect(failure.code).toBe('ECONNREFUSED');
    expect(failure.abortedBy).toBeNull();
  });

  it('reports a handshake that never answers as a tls-phase phase-timeout', async () => {
    const port = await listenSilent();
    const guard = new NetworkGuard(profile([endpoint('example.test', 443)]));
    guard.permit(LOOPBACK, port, 'fixture');

    const failure = expectFailure(
      await tlsCapturer.capture({ host: LOOPBACK, port }, captureOptions(guard, { tlsTimeoutMs: 50 })),
    );

    expect(failure.phase).toBe('tls');
    expect(failure.abortedBy).toBe('phase-timeout');
    expect(failure.code).toBeNull();
  });

  it('distinguishes the whole run being cancelled from this handshake hanging', async () => {
    const port = await listenSilent();
    const guard = new NetworkGuard(profile([endpoint('example.test', 443)]));
    guard.permit(LOOPBACK, port, 'fixture');
    const controller = new AbortController();
    const cancel = setTimeout(() => {
      controller.abort();
    }, 50);

    try {
      const failure = expectFailure(
        await tlsCapturer.capture({ host: LOOPBACK, port }, captureOptions(guard, { signal: controller.signal })),
      );

      expect(failure.phase).toBe('tls');
      expect(failure.abortedBy).toBe('run-signal');
    } finally {
      clearTimeout(cancel);
    }
  });

  it('refuses a host the profile never named, before any socket opens', async () => {
    const guard = new NetworkGuard(profile([endpoint('example.test', 443)]));

    await expect(tlsCapturer.capture({ host: 'elsewhere.test', port: 443 }, captureOptions(guard))).rejects.toThrow(
      /not named in the active profile/,
    );
  });
});
