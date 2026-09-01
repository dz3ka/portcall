import { describe, expect, it } from 'vitest';
import { runTruststore, truststoreProbe } from '../src/probes/truststore/index.ts';
import { PROBES } from '../src/engine/registry.ts';
import { NetworkGuard } from '../src/net/guard.ts';
import { derToPem } from '../src/net/pem.ts';
import type { ProbeContext } from '../src/engine/index.ts';
import type {
  OsTrustStoreReader,
  RuntimeStoreOutcome,
  RuntimeStoreReader,
  TrustStoreOutcome,
} from '../src/net/types.ts';
import type { LoadedProfile, Runtime } from '../src/profiles/schema.ts';
import { syntheticCert } from './helpers/synthetic-chain.ts';

/**
 * The `truststore` probe's *shell* (M4, WP6): the edge, over stubbed seams.
 *
 * What is under test here is only what the edge decides - which readers are
 * called, with what, and in what order the probe runs relative to `tls`. Every
 * verdict is `evaluate.ts`'s and is tested in `truststore-evaluate.test.ts`
 * against fixtures, which is the split ADR-0002 asks for.
 */

function loaded(runtimes: readonly Runtime[]): LoadedProfile {
  return {
    id: 'fixture',
    source: 'builtin',
    profile: {
      name: 'Fixture profile',
      endpoints: [
        { host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false },
      ],
      doh_resolvers: [],
      runtimes: [...runtimes],
      tls: { min_version: '1.2', interception_tolerated: true },
    },
  };
}

function context(profile: LoadedProfile, deadline: number = Date.now() + 60_000): ProbeContext {
  return {
    profile,
    net: new NetworkGuard(profile.profile),
    deadline,
    signal: new AbortController().signal,
    observedAnchors: [],
  };
}

interface OsCall {
  deadline: number;
  signal: AbortSignal;
}

function osReaderStub(outcomes: readonly TrustStoreOutcome[], calls: OsCall[] = []): OsTrustStoreReader {
  return {
    read(options: { signal: AbortSignal; deadline: number }): Promise<readonly TrustStoreOutcome[]> {
      calls.push({ deadline: options.deadline, signal: options.signal });
      return Promise.resolve(outcomes);
    },
  };
}

interface RuntimeCall {
  runtimes: readonly Runtime[];
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  maxBytes: number;
}

function runtimeReaderStub(
  outcomes: readonly RuntimeStoreOutcome[],
  calls: RuntimeCall[] = [],
): RuntimeStoreReader {
  return {
    read(
      runtimes: readonly Runtime[],
      options: { env: NodeJS.ProcessEnv; platform: NodeJS.Platform; maxBytes: number },
    ): Promise<readonly RuntimeStoreOutcome[]> {
      calls.push({ runtimes, ...options });
      return Promise.resolve(outcomes);
    },
  };
}

describe('truststore probe shell', () => {
  it('runs last, after the probe whose observations it reads', () => {
    expect(PROBES.map((probe) => probe.name)).toEqual(['dns', 'egress', 'proxy', 'tls', 'truststore']);
    expect(PROBES.at(-1)).toBe(truststoreProbe);
  });

  it("hands the reader the run's deadline and its signal, never a timeout of its own", async () => {
    const calls: OsCall[] = [];
    const deadline = Date.now() + 12_345;
    const ctx = context(loaded(['node']), deadline);

    await runTruststore(ctx, osReaderStub([], calls), runtimeReaderStub([]), [], {}, 'linux');

    expect(calls).toHaveLength(1);
    expect(calls[0]?.deadline).toBe(deadline);
    expect(calls[0]?.signal).toBe(ctx.signal);
  });

  it('asks the runtime reader for exactly the runtimes the profile declares', async () => {
    const calls: RuntimeCall[] = [];

    await runTruststore(
      context(loaded(['node', 'java'])),
      osReaderStub([]),
      runtimeReaderStub([], calls),
      [],
      { JAVA_HOME: '/opt/jdk-17' },
      'win32',
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]?.runtimes).toEqual(['node', 'java']);
    expect(calls[0]?.env).toEqual({ JAVA_HOME: '/opt/jdk-17' });
    expect(calls[0]?.platform).toBe('win32');
    expect(calls[0]?.maxBytes).toBeGreaterThan(0);
  });

  it('turns what the two readers returned into the cross-check verdict', async () => {
    const localRootPem = derToPem(await syntheticCert({ subject: 'CN=Acme Corp Internal Root, O=Acme Corp Ltd' }));
    const publicRootPem = derToPem(await syntheticCert({ subject: 'CN=Example Public Root CA' }));

    const findings = await runTruststore(
      context(loaded(['node'])),
      osReaderStub([
        {
          kind: 'linux-ca-bundle',
          locator: '/etc/ssl/certs/ca-certificates.crt',
          pems: [publicRootPem, localRootPem],
          failure: null,
          code: null,
          budgetMs: null,
          // A stub, so no read was performed to have taken any time.
          readMs: null,
        },
      ]),
      runtimeReaderStub([
        {
          runtime: 'node',
          kind: 'node-bundled',
          locator: null,
          searched: [],
          combines: 'standalone',
          pems: [publicRootPem],
          format: null,
          partial: false,
          failure: null,
          code: null,
        },
      ]),
      [publicRootPem],
      {},
      'linux',
    );

    expect(findings.map((finding) => `${finding.id}=${finding.severity}`)).toEqual([
      'truststore.os.read=ok',
      'truststore.node.missing-root=degraded',
    ]);
  });

  it('reports the platform rather than throwing when the reader has no store to offer', async () => {
    const findings = await runTruststore(
      context(loaded(['node'])),
      osReaderStub([]),
      runtimeReaderStub([]),
      [],
      {},
      'freebsd',
    );

    // The runtime reader is stubbed empty here, which is a *violated*
    // postcondition (every declared runtime is owed a row), so the probe says
    // so rather than staying silent about node.
    expect(findings.map((finding) => finding.id)).toEqual([
      'truststore.os.unreadable',
      'truststore.node.store-not-found',
      'truststore.crosscheck.indeterminate',
    ]);
  });

  it('is the probe the registry registers, and calls the same path the registry would', async () => {
    const findings = await truststoreProbe.run(context(loaded(['node'])));

    // The real readers run here: on any of the three target platforms this
    // reads a store, and on none of them may it throw - the seam turns every
    // failure into an outcome (ADR-0008), so the probe always has findings.
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.probe === 'truststore')).toBe(true);
  });
});
