import type { Probe, ProbeContext } from '../../engine/index.ts';
import type { Evidence, Finding, Severity } from '../../model/finding.ts';
import { systemResolver } from '../../net/dns.ts';
import { endpointProber } from '../../net/endpoint.ts';
import { DOH_PORT } from '../../net/guard.ts';
import type { DnsOutcome, DnsResolver, EndpointAttempt, EndpointProber } from '../../net/types.ts';
import { cap } from '../shared/severity.ts';
import { SLOW_RESOLUTION_MS, classifyAddress } from './analyse.ts';

/**
 * The DNS probe (M1): does every profile host resolve here, to what, how fast,
 * and - if the profile declares one - can the tool's own DoH resolver even be
 * reached.
 *
 * The resolver and the endpoint prober arrive as default parameters, the same
 * seam `main(argv, streams)` uses, so every row of the finding table is driven
 * by a recorded outcome instead of a socket.
 *
 * Hosts are resolved concurrently. A profile lists a handful of hosts and each
 * lookup can burn the full budget below against a black-hole resolver; doing
 * them in series would spend the whole run on the first two.
 */

/**
 * Per-lookup budget. `DnsResolver.resolve` takes a signal and no timeout, so
 * the probe owns the watchdog: an unanswered query is a finding about the
 * resolver, not a reason to lose the rest of the run.
 */
export const DNS_TIMEOUT_MS = 5000;

/**
 * Budgets for the DoH reachability attempt. Deliberately a local copy of the
 * egress probe's numbers rather than a shared constants module: these bound a
 * different question (is this resolver reachable at all) and are free to move
 * without dragging every endpoint check with them.
 */
const DOH_CONNECT_TIMEOUT_MS = 5000;
const DOH_TLS_TIMEOUT_MS = 5000;
const DOH_HTTP_TIMEOUT_MS = 10_000;

/**
 * Why a name did not resolve, in our own words.
 *
 * The `code` from the resolver is reported alongside this, but a code alone is
 * not a triage answer: `SERVFAIL` and `ENOTFOUND` send an operator to the same
 * team with two very different sentences, and a watchdog timeout carries no
 * code at all.
 */
export type ResolveFailure =
  | 'name-not-found'
  | 'no-address-records'
  | 'resolver-timeout'
  | 'resolver-refused'
  | 'unclassified';

/**
 * What the DoH check learned. Note what is *not* here: whether DoH resolution
 * works. This check proves TCP+TLS reachability of the resolver's HTTPS
 * endpoint and nothing more, and every string below is worded to keep that
 * distinction visible in the report.
 */
export type DohOutcome =
  | 'reachable'
  // Split the way the connect pair is: the resolver's own name failing to
  // resolve and our watchdog expiring on the lookup are different observations,
  // and neither may be reported as a cause - `SERVFAIL`, `ENODATA` and a
  // timeout all reached the old `blocked-dns-nxdomain`, which named one.
  | 'blocked-dns-failed'
  | 'blocked-dns-timeout'
  | 'blocked-connect-refused'
  | 'blocked-connect-timeout'
  | 'blocked-tls-failed'
  | 'indeterminate-deadline';

const NAME_NOT_FOUND_CODES: ReadonlySet<string> = new Set(['ENOTFOUND', 'NXDOMAIN']);
const NO_RECORD_CODES: ReadonlySet<string> = new Set(['ENODATA', 'EAI_NODATA']);
const TIMEOUT_CODES: ReadonlySet<string> = new Set(['ETIMEOUT', 'ETIMEDOUT', 'EAI_AGAIN']);
const REFUSED_CODES: ReadonlySet<string> = new Set(['SERVFAIL', 'REFUSED']);

/** Stand-in for a failure the resolver gave us no code for. Our string, not the network's. */
const NO_CODE = 'unavailable';

export const dnsProbe: Probe = {
  name: 'dns',
  run(context: ProbeContext): Promise<Finding[]> {
    return runDns(context);
  },
};

export async function runDns(
  context: ProbeContext,
  resolver: DnsResolver = systemResolver,
  prober: EndpointProber = endpointProber,
): Promise<Finding[]> {
  const { profile } = context.profile;

  const [hostFindings, dohFindings] = await Promise.all([
    Promise.all(distinctHosts(profile.endpoints).map((host) => checkHost(host, context, resolver))),
    Promise.all(profile.doh_resolvers.map((host) => checkDoh(host, context, prober))),
  ]);

  return [...hostFindings.flat(), ...dohFindings];
}

interface ProfileHost {
  host: string;
  /** True if *any* endpoint on this host is required: the strictest claim wins. */
  required: boolean;
}

/**
 * One lookup per distinct host, not per endpoint. A profile that lists
 * `api.example.com` on 443 and on 80 asks one DNS question, and resolving it
 * twice would put the same answer in the report twice.
 */
function distinctHosts(endpoints: readonly { host: string; required: boolean }[]): ProfileHost[] {
  const hosts = new Map<string, ProfileHost>();
  for (const endpoint of endpoints) {
    const existing = hosts.get(endpoint.host);
    if (existing === undefined) {
      hosts.set(endpoint.host, { host: endpoint.host, required: endpoint.required });
      continue;
    }
    existing.required = existing.required || endpoint.required;
  }
  return [...hosts.values()];
}

/** `SLOW_RESOLUTION_MS` is the threshold itself, not the first value below it. */
export function isSlowResolution(elapsedMs: number): boolean {
  return elapsedMs >= SLOW_RESOLUTION_MS;
}

async function checkHost(target: ProfileHost, context: ProbeContext, resolver: DnsResolver): Promise<Finding[]> {
  const outcome = await resolver.resolve(target.host, {
    signal: AbortSignal.any([context.signal, AbortSignal.timeout(DNS_TIMEOUT_MS)]),
    guard: context.net,
  });

  const findings = [verdict(target, outcome)];
  // Latency is orthogonal to the answer: a slow lookup that returns the right
  // address is still a deployment problem for a tool that re-resolves per
  // request, and a slow lookup that fails has already been reported as a
  // failure.
  if (outcome.ok && isSlowResolution(outcome.elapsedMs)) findings.push(slowResolution(target, outcome.elapsedMs));
  return findings;
}

function host(name: string): Evidence {
  return { label: 'host', value: name, kind: 'hostname' };
}

function verdict(target: ProfileHost, outcome: DnsOutcome): Finding {
  if (!outcome.ok) {
    // Checked before anything reads the code: a cancelled run taught us nothing
    // about this name, and every failure class below would be a claim.
    if (outcome.abortedBy === 'run-signal') return aborted(target.host);
    return resolveFailed(target, classifyResolveFailure(outcome), outcome.code);
  }

  // An answer with no address is a failure wearing a success's clothes: the
  // query was answered and the tool still has nowhere to connect.
  if (outcome.addresses.length === 0) return resolveFailed(target, 'no-address-records', null);

  const classes = outcome.addresses.map((address) => classifyAddress(address));

  const sinkholeAt = classes.indexOf('sinkhole');
  if (sinkholeAt !== -1) return sinkholed(target, outcome.addresses[sinkholeAt] ?? '');

  // `malformed` cannot appear here: the resolver seam drops any answer that is
  // not a parseable IP before it returns.
  if (classes.includes('private')) return splitHorizon(target, outcome.addresses);

  return {
    id: 'dns.resolved',
    probe: 'dns',
    severity: 'ok',
    title: 'The host resolves to a public address',
    evidence: [
      host(target.host),
      ...outcome.addresses.map((address): Evidence => ({ label: 'address', value: address, kind: 'ip' })),
      { label: 'elapsed (ms)', value: String(outcome.elapsedMs), kind: 'number' },
    ],
  };
}

export function classifyResolveFailure(outcome: Extract<DnsOutcome, { ok: false }>): ResolveFailure {
  const { code } = outcome;
  if (code !== null) {
    if (NAME_NOT_FOUND_CODES.has(code)) return 'name-not-found';
    if (NO_RECORD_CODES.has(code)) return 'no-address-records';
    if (TIMEOUT_CODES.has(code)) return 'resolver-timeout';
    if (REFUSED_CODES.has(code)) return 'resolver-refused';
  }
  // The watchdog firing is itself the observation: the resolver never answered.
  if (outcome.abortedBy === 'phase-timeout') return 'resolver-timeout';
  return 'unclassified';
}

function resolveFailed(target: ProfileHost, failure: ResolveFailure, code: string | null): Finding {
  return {
    id: 'dns.resolve-failed',
    probe: 'dns',
    severity: cap('blocker', target.required),
    title: 'The host does not resolve from this machine',
    evidence: [
      host(target.host),
      { label: 'failure', value: failure, kind: 'text' },
      { label: 'code', value: code ?? NO_CODE, kind: 'text' },
    ],
    remediation:
      'Nothing else about this endpoint can be trusted until the name resolves. Ask the team ' +
      'that runs DNS or Active Directory whether this zone is served on this network, and check ' +
      'whether a split-tunnel VPN is sending the query to a resolver that does not know it.',
  };
}

function sinkholed(target: ProfileHost, address: string): Finding {
  return {
    id: 'dns.sinkholed',
    probe: 'dns',
    severity: cap('blocker', target.required),
    title: 'The resolver returns a block address for this host',
    evidence: [host(target.host), { label: 'address', value: address, kind: 'ip' }],
    remediation:
      'This is a deliberate block, not a network fault: the resolver is handing out an address ' +
      'that goes nowhere, so no connection will ever be made. Request an allowlist entry for ' +
      'this fully qualified name from whoever runs DNS filtering.',
  };
}

function splitHorizon(target: ProfileHost, addresses: readonly string[]): Finding {
  return {
    id: 'dns.split-horizon',
    probe: 'dns',
    severity: 'degraded',
    title: 'The host resolves to an internal address',
    evidence: [
      host(target.host),
      ...addresses.map((address): Evidence => ({ label: 'address', value: address, kind: 'ip' })),
      { label: 'address class', value: 'private', kind: 'text' },
    ],
    remediation:
      'An internal answer is often correct - a corporate VIP or a mirror in front of the real ' +
      'service - but it is also how a transparent proxy inserts itself. Confirm with the team ' +
      'that owns this zone that the internal address terminates the same service; if it does ' +
      'not, ask them to serve the public answer here.',
  };
}

function slowResolution(target: ProfileHost, elapsedMs: number): Finding {
  return {
    id: 'dns.slow-resolution',
    probe: 'dns',
    severity: 'degraded',
    title: 'Resolving this host is slow enough for a user to notice',
    evidence: [host(target.host), { label: 'elapsed (ms)', value: String(elapsedMs), kind: 'number' }],
    remediation:
      'Ask the DNS team to look at resolver latency for this zone - a dead forwarder that has to ' +
      'time out before the next one is tried is the usual cause. Any tool that re-resolves per ' +
      'request will feel broken to users long before anything actually fails.',
  };
}

function aborted(name: string): Finding {
  return {
    id: 'dns.aborted',
    probe: 'dns',
    severity: 'unknown',
    title: 'The run ended before this host was resolved',
    evidence: [host(name)],
    remediation:
      'The global run budget expired before the resolver answered, so this is not a verdict ' +
      'about DNS. Re-run with a larger `--timeout`.',
  };
}

async function checkDoh(resolverHost: string, context: ProbeContext, prober: EndpointProber): Promise<Finding> {
  const attempt = await prober.attempt(
    { host: resolverHost, port: DOH_PORT, useTls: true },
    {
      signal: context.signal,
      guard: context.net,
      connectTimeoutMs: DOH_CONNECT_TIMEOUT_MS,
      tlsTimeoutMs: DOH_TLS_TIMEOUT_MS,
      httpTimeoutMs: DOH_HTTP_TIMEOUT_MS,
    },
  );
  return dohFinding(resolverHost, attempt);
}

/**
 * The verdict is defined at the TLS boundary, and reads only `ok`, `phase` and
 * `abortedBy`.
 *
 * Everything an enterprise does to stop DoH lands at or before that boundary:
 * an NXDOMAIN or blackhole for the resolver's own name (`dns`), a drop or reset
 * on 443 (`connect`), interception plus a policy reset (`tls`). Once the
 * handshake completed, whatever HTTP did afterwards is a different question -
 * this check sends no DoH query, so a 404 on `GET /` says nothing.
 */
export function evaluateDoh(attempt: EndpointAttempt): DohOutcome {
  if (attempt.ok) return 'reachable';
  // A cancelled run is not a verdict, and saying "blocked" on the strength of
  // our own deadline would be the worst kind of wrong answer here.
  if (attempt.abortedBy === 'run-signal') return 'indeterminate-deadline';

  switch (attempt.phase) {
    case 'dns':
      return attempt.abortedBy === 'phase-timeout' ? 'blocked-dns-timeout' : 'blocked-dns-failed';
    case 'connect':
      return attempt.abortedBy === 'phase-timeout' ? 'blocked-connect-timeout' : 'blocked-connect-refused';
    case 'tls':
      return 'blocked-tls-failed';
    case 'http':
      return 'reachable';
  }
}

interface DohVerdict {
  id: string;
  severity: Severity;
  title: string;
  remediation: string | null;
}

function dohVerdict(outcome: DohOutcome): DohVerdict {
  const blocked = (layer: string): DohVerdict => ({
    id: 'dns.doh-blocked',
    severity: 'degraded',
    // Never "DoH is blocked": what was measured is reachability of the
    // resolver's HTTPS endpoint, and the title may not claim more than that.
    title: `The declared DoH resolver's HTTPS endpoint is blocked at the ${layer} layer`,
    remediation:
      `This network blocks the declared DNS-over-HTTPS resolver at the ${layer} layer, which is ` +
      'normal corporate policy rather than a fault. Configure the tool to use the system ' +
      'resolver instead of its built-in DoH resolver, or - if DoH is genuinely required - ask ' +
      'the network team to allow TCP 443 to the resolver named in the evidence above. The tool ' +
      'still resolves names through the system resolver either way.',
  });

  switch (outcome) {
    case 'reachable':
      return {
        id: 'dns.doh-reachable',
        severity: 'ok',
        title: "The declared DoH resolver's HTTPS endpoint is reachable",
        remediation: null,
      };
    case 'blocked-dns-failed':
    case 'blocked-dns-timeout':
      return blocked('DNS');
    case 'blocked-connect-refused':
    case 'blocked-connect-timeout':
      return blocked('connect');
    case 'blocked-tls-failed':
      return blocked('TLS');
    case 'indeterminate-deadline':
      return {
        id: 'dns.doh-indeterminate',
        severity: 'unknown',
        title: "The declared DoH resolver's HTTPS endpoint check did not finish",
        remediation:
          "The run's global timeout expired before this check finished, so it is not a verdict " +
          'either way. Re-run with a larger `--timeout` before concluding anything about ' +
          'DNS-over-HTTPS on this network.',
      };
  }
}

function dohFinding(resolverHost: string, attempt: EndpointAttempt): Finding {
  const outcome = evaluateDoh(attempt);
  const { id, severity, title, remediation } = dohVerdict(outcome);

  const evidence: Evidence[] = [
    { label: 'resolver', value: resolverHost, kind: 'hostname' },
    { label: 'outcome', value: outcome, kind: 'text' },
  ];
  if (outcome === 'reachable' && attempt.timing.tlsMs !== null) {
    evidence.push({ label: 'TLS handshake (ms)', value: String(attempt.timing.tlsMs), kind: 'number' });
  }

  const finding: Finding = { id, probe: 'dns', severity, title, evidence };
  if (remediation !== null) finding.remediation = remediation;
  return finding;
}
