import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { NetworkGuard } from '../src/net/guard.ts';
import type { ProxyConnectDetail } from '../src/net/proxy-connect.ts';
import type { AttemptTiming, DnsOutcome, DnsResolver, PacFetchOutcome, PacFetcher, ProxyConnectAttempt } from '../src/net/types.ts';
import type { ProbeContext } from '../src/engine/index.ts';
import type { Finding } from '../src/model/finding.ts';
import { assertRemediable } from '../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../src/profiles/schema.ts';
import { classifyConnect, proxyProbe, runProxy } from '../src/probes/proxy/index.ts';
import type { PacSandbox } from '../src/probes/proxy/pac-sandbox.ts';
import { evaluatePac } from '../src/probes/proxy/pac.ts';
import type { PacContext, PacVerdict } from '../src/probes/proxy/pac.ts';

/**
 * Fixture-free but network-free: every case stubs the four injected seams
 * (`resolver`, `fetcher`, `connect`, `sandbox`) the same way
 * `test/probe-egress.test.ts` stubs `EndpointProber` - no socket, and no `vm`
 * execution of a hostile PAC script (that is `test/proxy-pac.test.ts`'s job,
 * and the Worker that bounds one is `test/proxy-pac-sandbox.test.ts`'s). The PAC
 * scripts used here are the same trivial `DIRECT`/`PROXY host:port` bodies
 * `test/proxy-pac.test.ts` exercises directly, run once each through the real,
 * non-hostile `evaluatePac` - in this thread rather than on a Worker, since
 * what these cases assert is the routing decision the verdict produces, not
 * how the script was executed. One case at the end deliberately omits the
 * seam, so the default `createPacSandbox()` wiring is exercised for real.
 */

const ENV_KEYS = ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'] as const;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

const NO_TIMING: AttemptTiming = { dnsMs: null, connectMs: null, tlsMs: null, httpMs: null };

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return { host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false, ...overrides };
}

function loaded(endpoints: Endpoint[], proxy?: { pac_url?: string }): LoadedProfile {
  const profile: Profile = {
    name: 'Fixture profile',
    endpoints,
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
    ...(proxy !== undefined ? { proxy } : {}),
  };
  return { id: 'fixture', source: 'builtin', profile };
}

function context(profile: LoadedProfile): ProbeContext {
  return {
    profile,
    net: new NetworkGuard(profile.profile),
    deadline: Date.now() + 60_000,
    signal: new AbortController().signal,
    observedAnchors: [],
  };
}

function resolverStub(outcome: DnsOutcome = { ok: true, addresses: ['93.184.216.34'], elapsedMs: 5 }, seen: string[] = []): DnsResolver {
  return {
    resolve: (host: string): Promise<DnsOutcome> => {
      seen.push(host);
      return Promise.resolve(outcome);
    },
  };
}

function pacFetcherStub(byUrl: Record<string, PacFetchOutcome>, seen: string[] = []): PacFetcher {
  return {
    fetch: (url: string): Promise<PacFetchOutcome> => {
      seen.push(url);
      const outcome = byUrl[url];
      if (outcome === undefined) throw new Error(`unexpected PAC fetch for ${url}`);
      return Promise.resolve(outcome);
    },
  };
}

const noPacFetch: PacFetcher = {
  fetch: (): Promise<PacFetchOutcome> => {
    throw new Error('the PAC fetcher must not be used on this discovery leg');
  },
};

interface ConnectCall {
  proxy: { host: string; port: number };
  target: { host: string; port: number };
}

function connectStub(
  detail: ProxyConnectDetail | ((call: ConnectCall) => ProxyConnectDetail),
  calls: ConnectCall[] = [],
) {
  return (proxy: { host: string; port: number }, target: { host: string; port: number }): Promise<ProxyConnectDetail> => {
    const call = { proxy, target };
    calls.push(call);
    return Promise.resolve(typeof detail === 'function' ? detail(call) : detail);
  };
}

const noConnect = (): Promise<ProxyConnectDetail> => {
  throw new Error('the proxy connector must not be used on this discovery leg');
};

function established(): ProxyConnectDetail {
  return { attempt: { ok: true, status: 200, timing: NO_TIMING }, proxyAuthenticate: null };
}

function failedAttempt(overrides: Partial<Extract<ProxyConnectAttempt, { ok: false }>>): ProxyConnectAttempt {
  return {
    ok: false,
    phase: 'connect',
    code: null,
    status: null,
    abortedBy: null,
    timing: NO_TIMING,
    ...overrides,
  };
}

const ALWAYS_DIRECT_PAC = 'function FindProxyForURL(url, host) { return "DIRECT"; }';
const ALWAYS_PROXY_PAC = 'function FindProxyForURL(url, host) { return "PROXY proxy.corp.internal:8080"; }';
const UNRESOLVED_PAC = 'function FindProxyForURL(url, host) { return 42; }';

interface PacEvalCall {
  url: string;
  host: string;
  timeoutMs: number;
}

/**
 * The `PacSandbox` seam these cases inject: the same `evaluatePac` the real
 * sandbox runs on its Worker, called in this thread instead. Recording the
 * arguments is the point as much as the verdict - the request URL, the host
 * and the evaluation budget the probe hands the sandbox are this file's to
 * assert, and what the Worker adds around that call is
 * `test/proxy-pac-sandbox.test.ts`'s.
 */
function sandboxStub(calls: PacEvalCall[] = []): PacSandbox {
  return {
    evaluate: (url: string, host: string, ctx: PacContext, timeoutMs: number): Promise<PacVerdict> => {
      calls.push({ url, host, timeoutMs });
      return Promise.resolve(evaluatePac(url, host, ctx, timeoutMs));
    },
  };
}

function findingIds(findings: Finding[]): string[] {
  return findings.map((f) => f.id);
}

/**
 * The destinations a finding actually claims something about, as
 * `host:port` - `endpoint`/`port` evidence is emitted in adjacent pairs, one
 * pair per destination that produced this finding's outcome.
 */
function claimedDestinations(finding: Finding | undefined): string[] {
  const evidence = finding?.evidence ?? [];
  const destinations: string[] = [];
  for (const [index, item] of evidence.entries()) {
    if (item.label !== 'endpoint') continue;
    const port = evidence[index + 1];
    expect(port?.label).toBe('port');
    destinations.push(`${item.value}:${String(port?.value)}`);
  }
  return destinations;
}

function rejected(): ProxyConnectDetail {
  return { attempt: failedAttempt({ phase: 'tunnel', status: 403, code: 'HTTP_403' }), proxyAuthenticate: null };
}

describe('proxy probe', () => {
  it('is registered under the name every finding id is prefixed with', () => {
    expect(proxyProbe.name).toBe('proxy');
  });

  it('emits nothing when the profile has no endpoints to check', async () => {
    const findings = await runProxy(context(loaded([])), resolverStub(), noPacFetch, noConnect);
    expect(findings).toEqual([]);
  });

  describe('discovery precedence: leg 1, explicit proxy.pac_url', () => {
    it('evaluates the PAC script and CONNECT-probes the discovered proxy', async () => {
      const seenUrls: string[] = [];
      const calls: ConnectCall[] = [];
      const fetcher = pacFetcherStub(
        { 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } },
        seenUrls,
      );
      const connect = connectStub(established(), calls);
      const pacCalls: PacEvalCall[] = [];

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        connect,
        sandboxStub(pacCalls),
      );

      expect(seenUrls).toEqual(['https://pac.corp.internal/proxy.pac']);
      expect(pacCalls).toEqual([{ url: 'https://api.example.com/', host: 'api.example.com', timeoutMs: 1000 }]);
      expect(findingIds(findings)).toEqual(['proxy.reachable']);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.proxy).toEqual({ host: 'proxy.corp.internal', port: 8080 });
      expect(calls[0]?.target).toEqual({ host: 'api.example.com', port: 443 });
    });

    it('resolves each endpoint host once and hands the same resolved target to every evaluation', async () => {
      const resolvedHosts: string[] = [];
      const pacCalls: PacEvalCall[] = [];
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(
          loaded([endpoint({ host: 'api.example.com', port: 443 }), endpoint({ host: 'api.example.com', port: 80 })], {
            pac_url: 'https://pac.corp.internal/proxy.pac',
          }),
        ),
        resolverStub(undefined, resolvedHosts),
        fetcher,
        connectStub(established()),
        sandboxStub(pacCalls),
      );

      // One lookup for the repeated host, but still one evaluation per
      // endpoint - the per-endpoint cache is about DNS, not about verdicts.
      expect(resolvedHosts).toEqual(['api.example.com']);
      expect(pacCalls.map((call) => call.url)).toEqual(['https://api.example.com/', 'http://api.example.com/']);
      expect(findingIds(findings)).toEqual(['proxy.reachable']);
    });

    it('evaluates the script on a real Worker sandbox when no seam is injected', async () => {
      // The one case that exercises `createPacSandbox()` itself through the
      // probe: a Worker that failed to load would answer `error` for every
      // endpoint, i.e. `proxy.pac-inconclusive` instead of the route below.
      const calls: ConnectCall[] = [];
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        connectStub(established(), calls),
      );

      expect(findingIds(findings)).toEqual(['proxy.reachable']);
      expect(calls[0]?.proxy).toEqual({ host: 'proxy.corp.internal', port: 8080 });
    });

    it('reports proxy.pac-fetch-failed and probes nothing else when the pac_url does not load', async () => {
      const fetcher = pacFetcherStub({
        'https://pac.corp.internal/proxy.pac': { ok: false, phase: 'connect', code: 'ECONNREFUSED', abortedBy: null, elapsedMs: 4 },
      });

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        noConnect,
      );

      expect(findingIds(findings)).toEqual(['proxy.pac-fetch-failed']);
      const finding = findings[0];
      expect(finding?.severity).toBe('degraded');
      expect(() => {
        assertRemediable(finding as Finding);
      }).not.toThrow();
    });

    it('reports proxy.pac-direct and never opens a CONNECT tunnel when the script says DIRECT', async () => {
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_DIRECT_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        noConnect,
        sandboxStub(),
      );

      expect(findingIds(findings)).toEqual(['proxy.pac-direct']);
      expect(findings[0]?.severity).toBe('ok');
    });

    it('reports proxy.pac-inconclusive when the script returns something unusable', async () => {
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: UNRESOLVED_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        noConnect,
        sandboxStub(),
      );

      expect(findingIds(findings)).toEqual(['proxy.pac-inconclusive']);
      expect(findings[0]?.severity).toBe('unknown');
    });
  });

  describe('discovery precedence: leg 2, HTTP_PROXY/HTTPS_PROXY env vars', () => {
    it('routes an HTTPS endpoint through HTTPS_PROXY without ever fetching a PAC script', async () => {
      process.env.HTTPS_PROXY = 'http://proxy.corp.internal:8080';
      const calls: ConnectCall[] = [];
      const connect = connectStub(established(), calls);

      const findings = await runProxy(context(loaded([endpoint()])), resolverStub(), noPacFetch, connect);

      expect(findingIds(findings)).toEqual(['proxy.reachable']);
      expect(calls[0]?.proxy).toEqual({ host: 'proxy.corp.internal', port: 8080 });
    });

    it('CONNECT-probes every (proxy, destination) pair, not one destination per proxy', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const calls: ConnectCall[] = [];
      const connect = connectStub(established(), calls);

      const findings = await runProxy(
        context(
          loaded([
            endpoint({ host: 'a.example.com', port: 80 }),
            endpoint({ host: 'b.example.com', port: 80 }),
            endpoint({ host: 'c.example.com', port: 80 }),
          ]),
        ),
        resolverStub(),
        noPacFetch,
        connect,
      );

      expect(calls.map((c) => c.target.host)).toEqual(['a.example.com', 'b.example.com', 'c.example.com']);
      expect(calls.every((c) => c.proxy.host === 'proxy.corp.internal')).toBe(true);
      // One finding per outcome, not per destination: three identical verdicts
      // roll up, and all three were measured.
      expect(findingIds(findings)).toEqual(['proxy.reachable']);
      expect(claimedDestinations(findings[0])).toEqual(['a.example.com:80', 'b.example.com:80', 'c.example.com:80']);
    });

    /**
     * A per-destination CONNECT ACL (`acl allowed dstdomain a.example.com`) is
     * ordinary squid configuration. A finding that named all three hosts off
     * one probe would be a false all-clear for two of them, or a false blocker
     * for the one that works.
     */
    it('splits one proxy into one finding per outcome, each naming only the destinations it measured', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const calls: ConnectCall[] = [];
      const connect = connectStub((call) => (call.target.host === 'a.example.com' ? established() : rejected()), calls);

      const findings = await runProxy(
        context(
          loaded([
            endpoint({ host: 'a.example.com', port: 80 }),
            endpoint({ host: 'b.example.com', port: 80 }),
            endpoint({ host: 'c.example.com', port: 80 }),
          ]),
        ),
        resolverStub(),
        noPacFetch,
        connect,
      );

      expect(calls).toHaveLength(3);
      expect(findingIds(findings)).toEqual(['proxy.reachable', 'proxy.connect-rejected']);
      expect(claimedDestinations(findings[0])).toEqual(['a.example.com:80']);
      expect(claimedDestinations(findings[1])).toEqual(['b.example.com:80', 'c.example.com:80']);
    });

    it('probes the same host once per declared port, because an ACL can differ by port', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const calls: ConnectCall[] = [];
      const connect = connectStub((call) => (call.target.port === 443 ? established() : rejected()), calls);

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'a.example.com', port: 443 }), endpoint({ host: 'a.example.com', port: 8080 })])),
        resolverStub(),
        noPacFetch,
        connect,
      );

      expect(calls.map((c) => c.target.port)).toEqual([443, 8080]);
      expect(claimedDestinations(findings.find((f) => f.id === 'proxy.reachable'))).toEqual(['a.example.com:443']);
      expect(claimedDestinations(findings.find((f) => f.id === 'proxy.connect-rejected'))).toEqual(['a.example.com:8080']);
    });

    it('probes a repeated (proxy, destination) pair only once', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const calls: ConnectCall[] = [];

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'a.example.com', port: 80 }), endpoint({ host: 'a.example.com', port: 80 })])),
        resolverStub(),
        noPacFetch,
        connectStub(established(), calls),
      );

      expect(calls).toHaveLength(1);
      expect(claimedDestinations(findings[0])).toEqual(['a.example.com:80']);
    });

    it('keeps the strictest severity when a required and an optional destination share an outcome', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';

      const findings = await runProxy(
        context(
          loaded([
            endpoint({ host: 'a.example.com', port: 80, required: false }),
            endpoint({ host: 'b.example.com', port: 80, required: true }),
          ]),
        ),
        resolverStub(),
        noPacFetch,
        connectStub(rejected()),
      );

      expect(findingIds(findings)).toEqual(['proxy.connect-rejected']);
      expect(findings[0]?.severity).toBe('blocker');
    });

    it('never reads a credential embedded in the proxy URL into evidence', async () => {
      process.env.HTTP_PROXY = 'http://svcacct:s3cret@proxy.corp.internal:3128';
      const findings = await runProxy(context(loaded([endpoint({ port: 80 })])), resolverStub(), noPacFetch, connectStub(established()));

      const text = JSON.stringify(findings);
      expect(text).not.toMatch(/s3cret|svcacct/);
    });

    it('validates NO_PROXY syntax and reports a malformed entry', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      process.env.NO_PROXY = 'valid.example.com,http://bad-scheme.example.com';

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'other.example.com', port: 80 })])),
        resolverStub(),
        noPacFetch,
        connectStub(established()),
      );

      expect(findingIds(findings)).toContain('proxy.no-proxy-syntax');
      const finding = findings.find((f) => f.id === 'proxy.no-proxy-syntax');
      expect(finding?.severity).toBe('degraded');
      expect(() => {
        assertRemediable(finding as Finding);
      }).not.toThrow();
    });

    it('bypasses the proxy for a host NO_PROXY names, and never opens a tunnel to it alone', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      process.env.NO_PROXY = 'bypassed.example.com';
      const calls: ConnectCall[] = [];

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'bypassed.example.com', port: 80 })])),
        resolverStub(),
        noPacFetch,
        connectStub(established(), calls),
      );

      expect(findingIds(findings)).toEqual(['proxy.no-proxy-bypass']);
      expect(calls).toHaveLength(0);
    });

    /**
     * The false all-clear this guards: a port-qualified entry that bypassed on
     * every port skipped the proxy check for an endpoint curl and Node would
     * route through the proxy, and reported `ok` while doing it.
     */
    it('does not bypass an endpoint whose port the NO_PROXY entry does not name', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      process.env.NO_PROXY = 'api.example.com:8080';
      const calls: ConnectCall[] = [];

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'api.example.com', port: 80 })])),
        resolverStub(),
        noPacFetch,
        connectStub(established(), calls),
      );

      expect(findingIds(findings)).toEqual(['proxy.reachable']);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.target).toEqual({ host: 'api.example.com', port: 80 });
    });

    it('bypasses only the endpoint on the port the NO_PROXY entry names', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      process.env.NO_PROXY = 'api.example.com:8080';
      const calls: ConnectCall[] = [];

      const findings = await runProxy(
        context(loaded([endpoint({ host: 'api.example.com', port: 8080 }), endpoint({ host: 'api.example.com', port: 80 })])),
        resolverStub(),
        noPacFetch,
        connectStub(established(), calls),
      );

      expect(findingIds(findings)).toEqual(['proxy.no-proxy-bypass', 'proxy.reachable']);
      expect(claimedDestinations(findings[0])).toEqual(['api.example.com:8080']);
      expect(calls.map((c) => c.target.port)).toEqual([80]);
    });
  });

  /**
   * `NO_PROXY` is applied on every discovery leg, not just the env-var one.
   * The tools portcall predicts for - curl, Node, python-requests - all honour
   * the variable and none of them evaluate a PAC script, so a host named in
   * `NO_PROXY` goes direct whatever the PAC says about it.
   */
  describe('NO_PROXY applies to the PAC-derived legs too', () => {
    it('bypasses a NO_PROXY host before the PAC script is ever asked about it (leg 1)', async () => {
      process.env.NO_PROXY = 'api.example.com';
      const pacCalls: PacEvalCall[] = [];
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(loaded([endpoint()], { pac_url: 'https://pac.corp.internal/proxy.pac' })),
        resolverStub(),
        fetcher,
        noConnect,
        sandboxStub(pacCalls),
      );

      expect(findingIds(findings)).toEqual(['proxy.no-proxy-bypass']);
      expect(pacCalls).toEqual([]);
    });

    it('bypasses a NO_PROXY host on the WPAD leg (leg 3)', async () => {
      process.env.NO_PROXY = 'api.example.com';
      const pacCalls: PacEvalCall[] = [];
      const fetcher = pacFetcherStub({ 'http://wpad/wpad.dat': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } });

      const findings = await runProxy(context(loaded([endpoint()])), resolverStub(), fetcher, noConnect, sandboxStub(pacCalls));

      expect(findingIds(findings)).toEqual(['proxy.no-proxy-bypass']);
      expect(pacCalls).toEqual([]);
    });

    it('still routes the endpoints NO_PROXY does not name through the PAC-derived proxy', async () => {
      process.env.NO_PROXY = 'a.example.com';
      const calls: ConnectCall[] = [];
      const fetcher = pacFetcherStub({ 'https://pac.corp.internal/proxy.pac': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } });

      const findings = await runProxy(
        context(
          loaded([endpoint({ host: 'a.example.com', port: 80 }), endpoint({ host: 'b.example.com', port: 80 })], {
            pac_url: 'https://pac.corp.internal/proxy.pac',
          }),
        ),
        resolverStub(),
        fetcher,
        connectStub(established(), calls),
        sandboxStub(),
      );

      expect(findingIds(findings)).toEqual(['proxy.no-proxy-bypass', 'proxy.reachable']);
      expect(calls.map((c) => c.target.host)).toEqual(['b.example.com']);
    });
  });

  describe('discovery precedence: leg 3, WPAD', () => {
    it('falls back to WPAD when there is no pac_url or env proxy, and evaluates the discovered PAC', async () => {
      const seenUrls: string[] = [];
      const fetcher = pacFetcherStub({ 'http://wpad/wpad.dat': { ok: true, script: ALWAYS_PROXY_PAC, elapsedMs: 4 } }, seenUrls);

      const findings = await runProxy(context(loaded([endpoint()])), resolverStub(), fetcher, connectStub(established()), sandboxStub());

      expect(seenUrls).toEqual(['http://wpad/wpad.dat']);
      expect(findingIds(findings)).toEqual(['proxy.reachable']);
    });
  });

  describe('discovery precedence: leg 4, none configured', () => {
    it('reports proxy.none-configured when the WPAD name does not resolve at all', async () => {
      const fetcher = pacFetcherStub({
        'http://wpad/wpad.dat': { ok: false, phase: 'dns', code: 'ENOTFOUND', abortedBy: null, elapsedMs: 4 },
      });

      const findings = await runProxy(context(loaded([endpoint()])), resolverStub(), fetcher, noConnect);

      expect(findingIds(findings)).toEqual(['proxy.none-configured']);
      expect(findings[0]?.severity).toBe('ok');
    });

    /**
     * The middle case between "no WPAD here" and "the configured PAC is
     * broken": something owns the `wpad` name and answers, but not with a
     * script. Reporting that as "no proxy is configured" is a false all-clear.
     */
    it.each([
      ['a 500 from the WPAD server', 'http' as const, 'HTTP_500'],
      ['a script too large to be one', 'http' as const, 'PAC_TOO_LARGE'],
      ['a refused connection to a resolvable wpad host', 'connect' as const, 'ECONNREFUSED'],
      ['a TLS failure on the WPAD hop', 'tls' as const, 'ERR_TLS_CERT_ALTNAME_INVALID'],
    ])('reports proxy.wpad-unusable, not none-configured, on %s', async (_label, phase, code) => {
      const fetcher = pacFetcherStub({
        'http://wpad/wpad.dat': { ok: false, phase, code, abortedBy: null, elapsedMs: 4 },
      });

      const findings = await runProxy(context(loaded([endpoint()])), resolverStub(), fetcher, noConnect);

      expect(findingIds(findings)).toEqual(['proxy.wpad-unusable']);
      expect(findings[0]?.severity).toBe('unknown');
      expect(findings[0]?.evidence.find((e) => e.label === 'code')?.value).toBe(code);
      expect(() => {
        assertRemediable(findings[0] as Finding);
      }).not.toThrow();
    });
  });

  describe('CONNECT outcome classification, via connectDetailed', () => {
    it.each([
      ['established', established(), 'proxy.reachable', 'ok'],
      [
        'auth-required (407 with Proxy-Authenticate)',
        { attempt: failedAttempt({ phase: 'tunnel', status: 407, code: 'HTTP_407' }), proxyAuthenticate: 'Basic realm="corp"' } satisfies ProxyConnectDetail,
        'proxy.auth-required',
        'degraded',
      ],
      [
        'rejected (403, no auth challenge)',
        { attempt: failedAttempt({ phase: 'tunnel', status: 403, code: 'HTTP_403' }), proxyAuthenticate: null } satisfies ProxyConnectDetail,
        'proxy.connect-rejected',
        'blocker',
      ],
      [
        'dns failure resolving the proxy',
        { attempt: failedAttempt({ phase: 'dns', code: 'ENOTFOUND' }), proxyAuthenticate: null } satisfies ProxyConnectDetail,
        'proxy.connect-dns-failure',
        'blocker',
      ],
      [
        'connection refused',
        { attempt: failedAttempt({ phase: 'connect', code: 'ECONNREFUSED' }), proxyAuthenticate: null } satisfies ProxyConnectDetail,
        'proxy.connect-refused',
        'blocker',
      ],
      [
        'silent timeout',
        { attempt: failedAttempt({ phase: 'connect', code: null, abortedBy: 'phase-timeout' }), proxyAuthenticate: null } satisfies ProxyConnectDetail,
        'proxy.connect-timeout',
        'blocker',
      ],
      [
        'unclassified failure',
        { attempt: failedAttempt({ phase: 'connect', code: 'EPROTO' }), proxyAuthenticate: null } satisfies ProxyConnectDetail,
        'proxy.connect-unclassified',
        'unknown',
      ],
    ] as const)('%s -> %s (%s)', async (_label, detail, id, severity) => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const findings = await runProxy(context(loaded([endpoint({ port: 80 })])), resolverStub(), noPacFetch, connectStub(detail));

      expect(findingIds(findings)).toEqual([id]);
      expect(findings[0]?.severity).toBe(severity);
      expect(() => {
        assertRemediable(findings[0] as Finding);
      }).not.toThrow();
    });

    it('names the classified auth scheme in the auth-required finding, never the raw header', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const detail: ProxyConnectDetail = {
        attempt: failedAttempt({ phase: 'tunnel', status: 407, code: 'HTTP_407' }),
        proxyAuthenticate: 'NTLM TlRMTVNTUAABAAAA',
      };

      const findings = await runProxy(context(loaded([endpoint({ port: 80 })])), resolverStub(), noPacFetch, connectStub(detail));

      const finding = findings[0];
      const schemeEvidence = finding?.evidence.find((e) => e.label === 'auth scheme');
      expect(schemeEvidence?.value).toBe('NTLM');
      const raw = JSON.stringify(finding);
      expect(raw).not.toContain('TlRMTVNTUAABAAAA');
    });

    it('reports proxy.aborted, not a failure classification, when the run signal ends the attempt', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const detail: ProxyConnectDetail = {
        attempt: failedAttempt({ phase: 'connect', code: null, abortedBy: 'run-signal' }),
        proxyAuthenticate: null,
      };

      const findings = await runProxy(context(loaded([endpoint({ port: 80 })])), resolverStub(), noPacFetch, connectStub(detail));

      expect(findingIds(findings)).toEqual(['proxy.aborted']);
      expect(findings[0]?.severity).toBe('unknown');
    });

    it('caps a blocker at degraded for an optional endpoint but never softens unknown', async () => {
      process.env.HTTP_PROXY = 'proxy.corp.internal:3128';
      const refused: ProxyConnectDetail = { attempt: failedAttempt({ phase: 'connect', code: 'ECONNREFUSED' }), proxyAuthenticate: null };
      const unclassified: ProxyConnectDetail = { attempt: failedAttempt({ phase: 'connect', code: 'EPROTO' }), proxyAuthenticate: null };

      const capped = await runProxy(
        context(loaded([endpoint({ port: 80, required: false })])),
        resolverStub(),
        noPacFetch,
        connectStub(refused),
      );
      expect(capped[0]?.severity).toBe('degraded');

      const stillUnknown = await runProxy(
        context(loaded([endpoint({ port: 80, required: false })])),
        resolverStub(),
        noPacFetch,
        connectStub(unclassified),
      );
      expect(stillUnknown[0]?.severity).toBe('unknown');
    });
  });

  describe('classifyConnect', () => {
    it('reaches every ProxyConnectClass member', () => {
      const cases: ProxyConnectAttempt[] = [
        { ok: true, status: 200, timing: NO_TIMING },
        failedAttempt({ phase: 'tunnel', status: 407, code: 'HTTP_407' }),
        failedAttempt({ phase: 'tunnel', status: 403, code: 'HTTP_403' }),
        failedAttempt({ phase: 'dns', code: 'ENOTFOUND' }),
        failedAttempt({ phase: 'connect', code: 'ECONNREFUSED' }),
        failedAttempt({ phase: 'connect', code: 'EHOSTUNREACH' }),
        failedAttempt({ phase: 'connect', code: null, abortedBy: 'phase-timeout' }),
        failedAttempt({ phase: 'connect', code: 'ECONNRESET' }),
        failedAttempt({ phase: 'connect', code: 'EPROTO' }),
      ];
      const produced = new Set(cases.map(classifyConnect));
      expect([...produced].sort()).toEqual(
        [
          'established',
          'auth-required',
          'rejected',
          'dns',
          'refused',
          'unreachable',
          'timeout',
          'reset',
          'unclassified',
        ].sort(),
      );
    });
  });
});
