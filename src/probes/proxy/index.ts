import { networkInterfaces } from 'node:os';
import type { Probe, ProbeContext } from '../../engine/index.ts';
import type { Evidence, Finding } from '../../model/finding.ts';
import { systemResolver } from '../../net/dns.ts';
import { pacFetcher } from '../../net/pac-fetch.ts';
import { connectDetailed } from '../../net/proxy-connect.ts';
import type { ProxyConnectDetail } from '../../net/proxy-connect.ts';
import type {
  AttemptOptions,
  AuthScheme,
  DnsResolver,
  EndpointAttempt,
  PacFetchOutcome,
  PacFetcher,
  ProxyConnectAttempt,
} from '../../net/types.ts';
import type { Endpoint } from '../../profiles/schema.ts';
import { classifyAttempt } from '../egress/classify.ts';
import { cap } from '../shared/severity.ts';
import { classifyAuthScheme } from './auth.ts';
import type { NoProxyEntry, NoProxyEntryIssue, NoProxyTarget } from './no-proxy.ts';
import { validateNoProxy } from './no-proxy.ts';
import { createPacSandbox } from './pac-sandbox.ts';
import type { PacSandbox } from './pac-sandbox.ts';
import { MAX_SCRIPT_BYTES } from './pac.ts';
import type { PacContext } from './pac.ts';

/**
 * The proxy probe (M2): discovers which proxy, if any, this machine is
 * expected to use for each declared endpoint, and whether that proxy actually
 * tunnels traffic to it. See the M2 handoff for the discovery precedence and
 * the seam decisions this file composes: `proxy.pac_url` (explicit) beats
 * `HTTP(S)_PROXY` (direct) beats WPAD (discovered) beats "no proxy in
 * effect". The pure judgment layer this file wires together lives in
 * `pac.ts`/`no-proxy.ts`/`auth.ts`; every socket this file touches goes
 * through `pacFetcher`/`connectDetailed`, both of which call
 * `NetworkGuard.permit()` for their runtime-discovered host before
 * connecting.
 *
 * PAC evaluation goes through the injected `sandbox` seam
 * (`pac-sandbox.ts`), never `evaluatePac` in this thread: `vm`'s own
 * `timeout` bounds synchronous execution only, so a script that keeps
 * looping through microtasks or `async` recursion answers this call and
 * then starves the event loop it ran on for the rest of the run. The
 * sandbox runs the same unchanged `evaluatePac` on a Worker thread it can
 * terminate, which is what actually bounds that (ADR-0017).
 *
 * The `connect` parameter is typed to `connectDetailed`'s own signature so
 * the test seam can stub it without a socket: the auth-scheme finding this
 * probe exists to produce needs the raw `Proxy-Authenticate` header, which
 * travels beside the attempt on `ProxyConnectDetail` (see
 * `src/net/proxy-connect.ts`'s module comment, "Seam decision for the
 * auth-scheme handoff").
 *
 * Two rules govern what a CONNECT finding may say. First, one CONNECT attempt
 * per `(proxy, destination)` pair, never one per proxy: per-destination ACLs
 * (`acl allowed dstdomain a.example.com`) are ordinary enterprise
 * configuration, so a verdict measured against one destination is not a
 * verdict about the others. Second, the attempts are then clustered by
 * *outcome*, so a proxy that behaves the same way for twenty endpoints still
 * produces one finding - and every destination that finding names is one
 * whose outcome was actually measured.
 */

export type ProxyConnectClass =
  | 'established'
  | 'auth-required'
  | 'rejected'
  | 'dns'
  | 'refused'
  | 'unreachable'
  | 'timeout'
  | 'reset'
  | 'unclassified';

type ProxyConnectFn = (
  proxy: { host: string; port: number },
  target: { host: string; port: number },
  options: AttemptOptions,
) => Promise<ProxyConnectDetail>;

/** WPAD discovery is DNS-based only (`http://wpad/wpad.dat`); DHCP option 252 is a stated M2 non-goal. */
const WPAD_URL = 'http://wpad/wpad.dat';

/** Generous headroom over how long a legitimate PAC script takes to run (sub-millisecond). */
const PAC_EVAL_TIMEOUT_MS = 1000;
/** Per-lookup budget for resolving an endpoint host before handing it to the PAC sandbox. */
const PAC_RESOLVE_TIMEOUT_MS = 5000;
const PROXY_CONNECT_TIMEOUT_MS = 5000;
/** Reused for the CONNECT round-trip; `AttemptOptions` carries no separate tunnel budget. */
const PROXY_TUNNEL_TIMEOUT_MS = 10_000;

const FALLBACK_LOCAL_ADDRESS = '127.0.0.1';
const NO_CODE = 'unavailable';

/** One `(proxy, destination)` pair to CONNECT-probe: the unit a verdict is actually true of. */
interface ProxyRoute {
  proxy: { host: string; port: number };
  target: { host: string; port: number };
  /** True if any endpoint declaring this route is required - the strictest claim wins. */
  required: boolean;
}

/** Every route through one proxy that produced the same outcome, reported as one finding. */
interface ProxyCluster {
  proxy: { host: string; port: number };
  targets: { host: string; port: number }[];
  required: boolean;
  verdict: ProxyConnectClass | 'aborted';
  /** `NO_CODE` when the outcome carried none. Part of the cluster key: two codes are two findings. */
  code: string;
  /** `none` unless the verdict is `auth-required`. Also part of the cluster key. */
  scheme: AuthScheme;
}

export const proxyProbe: Probe = {
  name: 'proxy',
  run(context: ProbeContext): Promise<Finding[]> {
    return runProxy(context);
  },
};

export async function runProxy(
  context: ProbeContext,
  resolver: DnsResolver = systemResolver,
  fetcher: PacFetcher = pacFetcher,
  connect: ProxyConnectFn = connectDetailed,
  sandbox: PacSandbox = createPacSandbox(),
): Promise<Finding[]> {
  const endpoints = context.profile.profile.endpoints;
  if (endpoints.length === 0) return [];

  const findings: Finding[] = [];

  // NO_PROXY syntax is validated whenever it is set, independent of which
  // discovery leg ends up in effect - SPEC.md 7 asks for the validation on
  // its own merits, not only when it changes a routing decision.
  const noProxyRaw = readEnvVar('NO_PROXY');
  const noProxyEntries = noProxyRaw !== null ? validateNoProxy(noProxyRaw, endpoints.map(targetOf)) : [];
  for (const entry of noProxyEntries) {
    if (entry.issue !== 'ok') findings.push(noProxySyntaxFinding(entry));
  }

  // A NO_PROXY hit removes the endpoint from *every* discovery leg, not just
  // the env-var one. The clients portcall is predicting for - curl, Node,
  // python-requests - all honour the variable and none of them evaluate a PAC
  // script, so an endpoint named in NO_PROXY goes direct whatever the PAC
  // says about it. (Browsers, which do evaluate PAC, keep their bypass list
  // and their PAC in separate settings; portcall does not predict for them.)
  const bypassed = new Set(
    noProxyEntries.filter((entry) => entry.issue === 'ok').flatMap((entry) => entry.matchedTargets).map(targetKey),
  );
  const bypassFindings = endpoints.filter((endpoint) => bypassed.has(targetKey(endpoint))).map(noProxyBypassFinding);
  const routedEndpoints = endpoints.filter((endpoint) => !bypassed.has(targetKey(endpoint)));

  const pacUrl = context.profile.profile.proxy?.pac_url ?? null;
  let routes: ProxyRoute[];

  if (pacUrl !== null) {
    const outcome = await fetcher.fetch(pacUrl, { signal: context.signal, guard: context.net, maxBytes: MAX_SCRIPT_BYTES });
    if (!outcome.ok) {
      findings.push(pacFetchFailedFinding(pacUrl, outcome));
      return findings;
    }
    findings.push(...bypassFindings);
    const evaluated = await evaluatePacPerEndpoint(outcome.script, routedEndpoints, context, resolver, sandbox);
    findings.push(...evaluated.directFindings, ...evaluated.inconclusiveFindings);
    routes = evaluated.routes;
  } else if (envProxyConfigured()) {
    findings.push(...bypassFindings);
    routes = envRoutes(routedEndpoints);
  } else {
    const wpad = await fetcher.fetch(WPAD_URL, { signal: context.signal, guard: context.net, maxBytes: MAX_SCRIPT_BYTES });
    if (wpad.ok) {
      findings.push(...bypassFindings);
      const evaluated = await evaluatePacPerEndpoint(wpad.script, routedEndpoints, context, resolver, sandbox);
      findings.push(...evaluated.directFindings, ...evaluated.inconclusiveFindings);
      routes = evaluated.routes;
    } else if (wpad.phase === 'dns') {
      // No `wpad` name on this network at all: the common case on most
      // networks, not a fault, and this leg stays silent about why. A failure
      // *after* the name resolved is a different story - see below.
      findings.push(noneConfiguredFinding());
      routes = [];
    } else {
      // The middle case between "no WPAD here" and "the configured PAC is
      // broken": the name resolved, something answered, and what came back
      // was not a usable script. Calling that "no proxy is configured" is a
      // false all-clear about the one thing this leg is trying to decide.
      findings.push(wpadUnusableFinding(wpad));
      routes = [];
    }
  }

  findings.push(...(await probeRoutes(routes, context, connect)));

  return findings;
}

function targetOf(endpoint: Endpoint): NoProxyTarget {
  return { host: endpoint.host, port: endpoint.port };
}

/** Case-insensitive `host:port` identity, for the NO_PROXY bypass set and the route dedup. */
function targetKey(target: { host: string; port: number }): string {
  return `${target.host.toLowerCase()}:${String(target.port)}`;
}

function addRoute(routes: Map<string, ProxyRoute>, proxy: { host: string; port: number }, endpoint: Endpoint): void {
  const key = `${targetKey(proxy)}|${targetKey(endpoint)}`;
  const existing = routes.get(key);
  if (existing === undefined) {
    routes.set(key, { proxy, target: targetOf(endpoint), required: endpoint.required });
    return;
  }
  // The same destination declared twice is still one tunnel to test; the
  // strictest `required` of the two decides how loudly a failure is reported.
  existing.required = existing.required || endpoint.required;
}

// --- PAC discovery (leg 1 and leg 3) ----------------------------------------

interface PacEvalResult {
  directFindings: Finding[];
  inconclusiveFindings: Finding[];
  routes: ProxyRoute[];
}

async function evaluatePacPerEndpoint(
  scriptText: string,
  endpoints: readonly Endpoint[],
  context: ProbeContext,
  resolver: DnsResolver,
  sandbox: PacSandbox,
): Promise<PacEvalResult> {
  const directFindings: Finding[] = [];
  const inconclusiveFindings: Finding[] = [];
  const routes = new Map<string, ProxyRoute>();
  const resolvedCache = new Map<string, PacContext['resolvedTarget']>();
  const myAddress = firstNonInternalAddress();

  for (const endpoint of endpoints) {
    let resolvedTarget = resolvedCache.get(endpoint.host);
    if (resolvedTarget === undefined) {
      resolvedTarget = await resolveForPac(endpoint.host, context, resolver);
      resolvedCache.set(endpoint.host, resolvedTarget);
    }

    const url = `${endpoint.port === 443 ? 'https' : 'http'}://${endpoint.host}/`;
    const verdict = await sandbox.evaluate(
      url,
      endpoint.host,
      { scriptText, resolvedTarget, myAddress, now: new Date() },
      PAC_EVAL_TIMEOUT_MS,
    );

    if (verdict.kind === 'direct') {
      directFindings.push(pacDirectFinding(endpoint));
      continue;
    }
    if (verdict.kind === 'unresolved' || verdict.kind === 'error') {
      inconclusiveFindings.push(pacInconclusiveFinding(endpoint, verdict.kind));
      continue;
    }
    addRoute(routes, { host: verdict.host, port: verdict.port }, endpoint);
  }

  return { directFindings, inconclusiveFindings, routes: [...routes.values()] };
}

async function resolveForPac(host: string, context: ProbeContext, resolver: DnsResolver): Promise<PacContext['resolvedTarget']> {
  const outcome = await resolver.resolve(host, {
    signal: AbortSignal.any([context.signal, AbortSignal.timeout(PAC_RESOLVE_TIMEOUT_MS)]),
    guard: context.net,
  });
  if (!outcome.ok || outcome.addresses.length === 0) return null;
  return { host, addresses: outcome.addresses };
}

/** `os.networkInterfaces()` is local machine state, not a network call - no `NetworkGuard` involvement. */
function firstNonInternalAddress(): string {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (!address.internal && address.family === 'IPv4') return address.address;
    }
  }
  return FALLBACK_LOCAL_ADDRESS;
}

// --- env-var discovery (leg 2) ----------------------------------------------

function readEnvVar(name: string): string | null {
  const value = process.env[name] ?? process.env[name.toLowerCase()];
  const trimmed = value?.trim();
  return trimmed !== undefined && trimmed !== '' ? trimmed : null;
}

function envProxyConfigured(): boolean {
  return readEnvVar('HTTPS_PROXY') !== null || readEnvVar('HTTP_PROXY') !== null;
}

/**
 * `HTTP_PROXY`/`HTTPS_PROXY` values routinely carry embedded Basic auth
 * (`http://user:pass@proxy:8080`, curl's own convention) - only `.hostname`
 * and `.port` are ever read off the parsed URL, never `.username`/
 * `.password`, so a credential in the env var cannot reach a finding.
 */
function parseProxyUrl(raw: string): { host: string; port: number } | null {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const parsed = new URL(withScheme);
    if (parsed.hostname === '') return null;
    const port = parsed.port !== '' ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
    return { host: parsed.hostname, port };
  } catch {
    return null;
  }
}

function envRoutes(endpoints: readonly Endpoint[]): ProxyRoute[] {
  const routes = new Map<string, ProxyRoute>();
  for (const endpoint of endpoints) {
    const proxy = envProxyFor(endpoint);
    if (proxy !== null) addRoute(routes, proxy, endpoint);
  }
  return [...routes.values()];
}

function envProxyFor(endpoint: Endpoint): { host: string; port: number } | null {
  const primaryName = endpoint.port === 443 ? 'HTTPS_PROXY' : 'HTTP_PROXY';
  const fallbackName = endpoint.port === 443 ? 'HTTP_PROXY' : 'HTTPS_PROXY';
  const primary = readEnvVar(primaryName);
  const fallback = readEnvVar(fallbackName);
  const raw = primary ?? fallback;
  return raw !== null ? parseProxyUrl(raw) : null;
}

// --- CONNECT probing ---------------------------------------------------------

/**
 * `attempt.phase` here is `dns`|`connect`|`tunnel` in practice
 * (`proxy-connect.ts` never produces `tls`, and `http` is not a phase of
 * this attempt) - pre-tunnel phases are handed to `classifyAttempt`
 * (`egress/classify.ts`), reusing its DNS/refused/unreachable/timeout/reset
 * table wholesale rather than duplicating it, per the M2 design decision.
 * The `tunnel` phase is this file's own call: a 407 names an auth challenge,
 * anything else non-2xx is the proxy declining to tunnel.
 */
export function classifyConnect(attempt: ProxyConnectAttempt): ProxyConnectClass {
  if (attempt.ok) return 'established';
  if (attempt.phase === 'tunnel') return attempt.status === 407 ? 'auth-required' : 'rejected';

  const asEndpointAttempt: EndpointAttempt = {
    ok: false,
    phase: attempt.phase,
    code: attempt.code,
    abortedBy: attempt.abortedBy,
    addresses: [],
    status: attempt.status,
    timing: attempt.timing,
  };
  switch (classifyAttempt(asEndpointAttempt)) {
    case 'dns':
      return 'dns';
    case 'refused':
      return 'refused';
    case 'unreachable':
      return 'unreachable';
    case 'timeout':
      return 'timeout';
    case 'reset':
      return 'reset';
    // `ok` cannot occur - `attempt.ok` was already checked above - and `tls`/
    // `http` cannot occur either: `proxy-connect.ts` never produces those
    // phases (see its module comment). `unclassified` is the honest landing
    // place for anything this table does not name.
    case 'ok':
    case 'tls':
    case 'http':
    case 'unclassified':
      return 'unclassified';
  }
}

/** One route's measured outcome, before findings are clustered by it. */
interface RouteOutcome {
  route: ProxyRoute;
  verdict: ProxyConnectClass | 'aborted';
  code: string;
  scheme: AuthScheme;
}

async function probeRoutes(routes: readonly ProxyRoute[], context: ProbeContext, connect: ProxyConnectFn): Promise<Finding[]> {
  const outcomes: RouteOutcome[] = [];
  for (const route of routes) outcomes.push(await probeRoute(route, context, connect));
  return cluster(outcomes).map(connectVerdictFinding);
}

async function probeRoute(route: ProxyRoute, context: ProbeContext, connect: ProxyConnectFn): Promise<RouteOutcome> {
  const detail = await connect(route.proxy, route.target, {
    signal: context.signal,
    guard: context.net,
    connectTimeoutMs: PROXY_CONNECT_TIMEOUT_MS,
    tlsTimeoutMs: PROXY_CONNECT_TIMEOUT_MS,
    httpTimeoutMs: PROXY_TUNNEL_TIMEOUT_MS,
  });

  // Checked before the classifier, same as egress/dns: a cancelled run is not
  // an observation about this proxy.
  if (!detail.attempt.ok && detail.attempt.abortedBy === 'run-signal') {
    return { route, verdict: 'aborted', code: NO_CODE, scheme: 'none' };
  }

  const verdict = classifyConnect(detail.attempt);
  return {
    route,
    verdict,
    code: detail.attempt.ok ? NO_CODE : (detail.attempt.code ?? NO_CODE),
    // The scheme is classified here rather than in the finding builder so it
    // is part of the cluster key: a proxy demanding Basic for one destination
    // and NTLM for another has told us two different things.
    scheme: verdict === 'auth-required' ? classifyAuthScheme(detail.proxyAuthenticate) : 'none',
  };
}

/**
 * Roll the per-route outcomes up into one finding per distinct
 * `(proxy, verdict, code, scheme)`. Anything that would read differently in a
 * report is part of the key, so a cluster's destinations are exactly the ones
 * the finding's text is true of - the invariant that makes reporting several
 * destinations in one finding honest rather than merely shorter.
 */
function cluster(outcomes: readonly RouteOutcome[]): ProxyCluster[] {
  const clusters = new Map<string, ProxyCluster>();
  for (const outcome of outcomes) {
    const key = [targetKey(outcome.route.proxy), outcome.verdict, outcome.code, outcome.scheme].join('|');
    const existing = clusters.get(key);
    if (existing === undefined) {
      clusters.set(key, {
        proxy: outcome.route.proxy,
        targets: [outcome.route.target],
        required: outcome.route.required,
        verdict: outcome.verdict,
        code: outcome.code,
        scheme: outcome.scheme,
      });
      continue;
    }
    existing.targets.push(outcome.route.target);
    existing.required = existing.required || outcome.route.required;
  }
  return [...clusters.values()];
}

/**
 * The proxy, then one `endpoint`/`port` pair per destination this cluster
 * actually measured. Destinations are paired rather than listed as bare
 * hostnames because a CONNECT ACL can allow a host on 443 and refuse it on
 * 8080, and a reader has to be able to tell which one this finding is about.
 */
function proxyEvidence(cluster: ProxyCluster): Evidence[] {
  return [
    { label: 'proxy', value: cluster.proxy.host, kind: 'hostname' },
    { label: 'proxy port', value: String(cluster.proxy.port), kind: 'number' },
    ...cluster.targets.flatMap((target): Evidence[] => [
      { label: 'endpoint', value: target.host, kind: 'hostname' },
      { label: 'port', value: String(target.port), kind: 'number' },
    ]),
  ];
}

function connectVerdictFinding(cluster: ProxyCluster): Finding {
  const evidence = proxyEvidence(cluster);
  const code = cluster.code;

  switch (cluster.verdict) {
    case 'established':
      return {
        id: 'proxy.reachable',
        probe: 'proxy',
        severity: 'ok',
        title: 'The discovered proxy accepts a CONNECT tunnel to these destinations',
        evidence,
      };

    case 'auth-required':
      return {
        id: 'proxy.auth-required',
        probe: 'proxy',
        severity: cap('degraded', cluster.required),
        title: 'The proxy demands authentication before it will tunnel this traffic',
        evidence: [...evidence, { label: 'auth scheme', value: cluster.scheme, kind: 'text' }],
        remediation:
          'Portcall never authenticates to a proxy (SPEC.md 4), so this only names the challenge ' +
          'above. Configure the credential for that scheme in the tool being deployed, or ask ' +
          'whoever administers the proxy whether an unauthenticated path exists for automation.',
      };

    case 'rejected':
      return {
        id: 'proxy.connect-rejected',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'The proxy refused to tunnel a connection to these destinations',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'The proxy answered the CONNECT request itself rather than tunnelling it, which is a ' +
          'policy decision, not a network fault. Ask whoever administers the proxy which rule ' +
          'matched these destinations and request an allowlist entry for them.',
      };

    case 'dns':
      return {
        id: 'proxy.connect-dns-failure',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'The proxy hostname does not resolve from this machine',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Name resolution for the proxy itself has to work before anything routed through it can. ' +
          'Ask the team that runs DNS whether this proxy name is served on this network, and check ' +
          'for a stale PAC/WPAD entry or a split-tunnel VPN sending the query to the wrong resolver.',
      };

    case 'refused':
      return {
        id: 'proxy.connect-refused',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'The connection to the proxy was refused',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Something answered "no" rather than dropping the packet, which is what a firewall rule ' +
          'or a proxy that is not actually listening looks like. Confirm the proxy host and port ' +
          'with whoever administers it, and request an outbound rule if one is missing.',
      };

    case 'unreachable':
      return {
        id: 'proxy.connect-unreachable',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'There is no route from this network to the proxy',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'The packet had nowhere to go: this is routing or NAT, not a policy decision about the ' +
          'proxy. Take it to the network team with the proxy host and code above.',
      };

    case 'timeout':
      return {
        id: 'proxy.connect-timeout',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'The attempt to reach the proxy timed out with no answer at all',
        evidence,
        remediation:
          'Silence rather than a refusal usually means a dropped packet somewhere on the path to ' +
          'the proxy. Ask the network team to check for a firewall rule dropping this destination, ' +
          'and confirm the proxy host and port are current.',
      };

    case 'reset':
      return {
        id: 'proxy.connect-reset',
        probe: 'proxy',
        severity: cap('blocker', cluster.required),
        title: 'The connection to the proxy was reset mid-flight',
        evidence,
        remediation:
          'A connection that opens and is then torn down is usually an inline appliance deciding it ' +
          'does not like this traffic. Ask whoever owns the network path to the proxy which rule fired.',
      };

    case 'unclassified':
      return {
        id: 'proxy.connect-unclassified',
        probe: 'proxy',
        severity: 'unknown',
        title: 'The proxy connection failed in a way portcall does not recognise',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Portcall has no mapping for this failure, and guessing would send you to the wrong team. ' +
          'Send this report to the tool vendor: the code above is enough for them to add the case.',
      };

    case 'aborted':
      return {
        id: 'proxy.aborted',
        probe: 'proxy',
        severity: 'unknown',
        title: 'The run ended before this proxy was checked',
        evidence,
        remediation:
          'The global run budget expired before the proxy CONNECT attempt got an answer, so nothing ' +
          'here is a verdict about the proxy. Re-run with a larger --timeout.',
      };
  }
}

// --- discovery-outcome findings that are not about a CONNECT attempt --------

function pacFetchFailedFinding(url: string, outcome: Extract<PacFetchOutcome, { ok: false }>): Finding {
  return {
    id: 'proxy.pac-fetch-failed',
    probe: 'proxy',
    severity: 'degraded',
    title: "The profile's configured PAC script could not be fetched",
    evidence: [
      { label: 'pac url', value: url, kind: 'url' },
      { label: 'phase', value: outcome.phase, kind: 'text' },
      { label: 'code', value: outcome.code ?? NO_CODE, kind: 'text' },
    ],
    remediation:
      "The PAC script named in the profile's `proxy.pac_url` did not load, so this run cannot know " +
      'which endpoints route through a proxy. Ask whoever manages PAC/WPAD on this network to ' +
      'confirm the URL above is reachable and serves the script over HTTP(S).',
  };
}

function pacInconclusiveFinding(endpoint: Endpoint, kind: 'unresolved' | 'error'): Finding {
  return {
    id: 'proxy.pac-inconclusive',
    probe: 'proxy',
    severity: 'unknown',
    title: 'The PAC script did not return a usable route for this endpoint',
    evidence: [
      { label: 'endpoint', value: endpoint.host, kind: 'hostname' },
      { label: 'pac verdict', value: kind, kind: 'text' },
    ],
    remediation:
      'The PAC script ran but did not answer `DIRECT` or `PROXY host:port` for this host, so ' +
      'whether it goes through a proxy is unknown. Ask whoever owns the PAC script to check its ' +
      'handling of this hostname.',
  };
}

function pacDirectFinding(endpoint: Endpoint): Finding {
  return {
    id: 'proxy.pac-direct',
    probe: 'proxy',
    severity: 'ok',
    title: 'The PAC script routes this endpoint directly, without a proxy',
    evidence: [{ label: 'endpoint', value: endpoint.host, kind: 'hostname' }],
  };
}

/** The port is named as well as the host: a NO_PROXY entry may exempt one port and not another. */
function noProxyBypassFinding(endpoint: Endpoint): Finding {
  return {
    id: 'proxy.no-proxy-bypass',
    probe: 'proxy',
    severity: 'ok',
    title: 'NO_PROXY exempts this endpoint from the configured proxy',
    evidence: [
      { label: 'endpoint', value: endpoint.host, kind: 'hostname' },
      { label: 'port', value: String(endpoint.port), kind: 'number' },
    ],
  };
}

/**
 * WPAD answered, but not with a script this run could use. Severity is
 * `unknown`, not `degraded`: portcall has not learned that the network is
 * broken - clients may well fall back to a direct connection and be fine -
 * it has learned that it cannot say which endpoints route through a proxy,
 * which is exactly what `unknown` means in this report ("the check could not
 * decide"). `unknown` is also never softened by `cap()`, and reporting
 * `proxy.none-configured` here instead would be an `ok` finding asserting the
 * opposite of what was observed.
 */
function wpadUnusableFinding(outcome: Extract<PacFetchOutcome, { ok: false }>): Finding {
  return {
    id: 'proxy.wpad-unusable',
    probe: 'proxy',
    severity: 'unknown',
    title: 'A WPAD server answered but this run got no usable PAC script from it',
    evidence: [
      // Our own constant, not a value read off this machine - `public`, so it
      // survives redaction and the reader can see what was probed.
      { label: 'wpad url', value: WPAD_URL, kind: 'public' },
      { label: 'phase', value: outcome.phase, kind: 'text' },
      { label: 'code', value: outcome.code ?? NO_CODE, kind: 'text' },
    ],
    remediation:
      'The `wpad` name resolves on this network and something answered on it, but not with a PAC ' +
      'script this run could use (the phase and code above say where it stopped), so portcall ' +
      'cannot tell which endpoints route through a proxy. Ask whoever manages WPAD here whether ' +
      'that server is still meant to serve one; if it is not, retiring the `wpad` DNS record stops ' +
      'every client on this network waiting on it.',
  };
}

function noneConfiguredFinding(): Finding {
  return {
    id: 'proxy.none-configured',
    probe: 'proxy',
    severity: 'ok',
    title: 'No proxy is configured for this network',
    evidence: [],
  };
}

function noProxyIssueDescription(issue: NoProxyEntryIssue): string {
  switch (issue) {
    case 'empty':
      return 'is empty (an extra comma, most likely)';
    case 'contains-scheme':
      return 'includes a URL scheme (`http://`), which NO_PROXY entries must not carry';
    case 'contains-port-with-wildcard':
      return 'combines a leading wildcard with a port, which no HTTP client parses consistently';
    case 'invalid-hostname':
      return 'is not a valid hostname, domain suffix or CIDR block';
    case 'wildcard-not-leading':
      return 'has a `*` outside the leading position, which most HTTP clients do not special-case';
    case 'ok':
      /* c8 ignore next */
      return 'parses correctly';
  }
}

function noProxySyntaxFinding(entry: NoProxyEntry): Finding {
  return {
    id: 'proxy.no-proxy-syntax',
    probe: 'proxy',
    severity: 'degraded',
    title: 'A NO_PROXY entry does not parse',
    evidence: [
      { label: 'entry', value: entry.raw, kind: 'hostname' },
      { label: 'issue', value: entry.issue, kind: 'text' },
    ],
    remediation:
      `This NO_PROXY entry ${noProxyIssueDescription(entry.issue)}. Fix it in the environment ` +
      'configuration that sets NO_PROXY on this machine; portcall reads it but never edits it.',
  };
}
