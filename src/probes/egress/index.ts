import type { Probe, ProbeContext } from '../../engine/index.ts';
import type { Evidence, Finding } from '../../model/finding.ts';
import type { AttemptPhase, AttemptTiming, EndpointAttempt, EndpointProber } from '../../net/types.ts';
import { endpointProber } from '../../net/endpoint.ts';
import type { Endpoint } from '../../profiles/schema.ts';
import { cap, classifyAttempt, classifyStatus } from './classify.ts';

/**
 * The egress probe (M1): can this machine actually reach every endpoint the
 * profile declares, and if not, which layer stopped it.
 *
 * All I/O goes through `EndpointProber`, which arrives as a default parameter
 * on `runEgress` exactly like `main(argv, streams)` takes its streams - so the
 * whole finding table below is exercised from recorded attempts with no socket
 * and no mocking framework.
 *
 * Every endpoint is attempted concurrently. Sequentially, a profile with a
 * dozen endpoints behind a silent firewall would spend twelve connect timeouts
 * against a 60s global budget and report almost nothing.
 */

/** Per-phase budgets. Deliberately well inside `--timeout`'s 60s default. */
const CONNECT_TIMEOUT_MS = 5000;
const TLS_TIMEOUT_MS = 5000;
const HTTP_HEADERS_TIMEOUT_MS = 10_000;

/** The one port that implies TLS without a scheme to say so. */
const TLS_PORT = 443;

/**
 * `getProtocol()` is Node's own vocabulary, not the peer's, but it is still a
 * string arriving from outside this module - so only these values reach
 * evidence. Anything else is dropped rather than passed through, because `text`
 * evidence crosses the redaction boundary verbatim.
 */
const TLS_PROTOCOLS: ReadonlySet<string> = new Set(['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']);

/** Stand-in for a failure the OS gave us no code for. Our string, not the peer's. */
const NO_CODE = 'unavailable';

type FailedAttempt = Extract<EndpointAttempt, { ok: false }>;

export const egressProbe: Probe = {
  name: 'egress',
  run(context: ProbeContext): Promise<Finding[]> {
    return runEgress(context);
  },
};

export async function runEgress(
  context: ProbeContext,
  prober: EndpointProber = endpointProber,
): Promise<Finding[]> {
  return Promise.all(
    context.profile.profile.endpoints.map((endpoint) => reach(endpoint, context, prober)),
  );
}

async function reach(endpoint: Endpoint, context: ProbeContext, prober: EndpointProber): Promise<Finding> {
  const attempt = await prober.attempt(
    { host: endpoint.host, port: endpoint.port, useTls: endpoint.port === TLS_PORT },
    {
      signal: context.signal,
      guard: context.net,
      connectTimeoutMs: CONNECT_TIMEOUT_MS,
      tlsTimeoutMs: TLS_TIMEOUT_MS,
      httpTimeoutMs: HTTP_HEADERS_TIMEOUT_MS,
    },
  );
  return judge(endpoint, attempt);
}

/** Total time the attempt spent, across the phases it actually reached. */
function totalMs(timing: AttemptTiming): number {
  return [timing.dnsMs, timing.connectMs, timing.tlsMs, timing.httpMs].reduce<number>(
    (total, phase) => total + (phase ?? 0),
    0,
  );
}

/**
 * Host and port lead every finding. The host is `hostname` evidence and never
 * part of the id or the title: ids are API that customers grep for, and a title
 * carrying an internal name would survive redaction.
 */
function where(endpoint: Endpoint): Evidence[] {
  return [
    { label: 'endpoint', value: endpoint.host, kind: 'hostname' },
    { label: 'port', value: String(endpoint.port), kind: 'number' },
  ];
}

function judge(endpoint: Endpoint, attempt: EndpointAttempt): Finding {
  if (attempt.ok) return succeeded(endpoint, attempt);
  // Checked before the classifier: a cancelled run is not an observation about
  // this endpoint, and `unknown` says so where any failure class would lie.
  if (attempt.abortedBy === 'run-signal') return aborted(endpoint);
  return failed(endpoint, attempt);
}

function succeeded(endpoint: Endpoint, attempt: Extract<EndpointAttempt, { ok: true }>): Finding {
  const { status } = attempt;
  if (status !== null && classifyStatus(status) === 'http') return httpError(endpoint, status);

  const evidence = where(endpoint);
  if (status !== null) evidence.push({ label: 'status', value: String(status), kind: 'number' });
  if (attempt.tlsProtocol !== null && TLS_PROTOCOLS.has(attempt.tlsProtocol)) {
    evidence.push({ label: 'TLS protocol', value: attempt.tlsProtocol, kind: 'text' });
  }
  evidence.push({ label: 'elapsed (ms)', value: String(totalMs(attempt.timing)), kind: 'number' });

  return {
    id: 'egress.reachable',
    probe: 'egress',
    severity: 'ok',
    title: 'The endpoint is reachable on its declared port',
    evidence,
  };
}

function httpError(endpoint: Endpoint, status: number | null): Finding {
  const evidence = where(endpoint);
  if (status !== null) evidence.push({ label: 'status', value: String(status), kind: 'number' });

  return {
    id: 'egress.http-error',
    probe: 'egress',
    severity: cap('blocker', endpoint.required),
    title: 'The HTTP response came from something other than the origin',
    evidence,
    remediation:
      'This status is what a proxy or filtering appliance returns when it answers on the ' +
      "origin's behalf, so the connection reached the intermediary and stopped there. Ask the " +
      'proxy team which policy matched this endpoint, and re-run once it is allowed. The proxy ' +
      'probe (M2) names the intermediary directly.',
  };
}

function aborted(endpoint: Endpoint): Finding {
  return {
    id: 'egress.aborted',
    probe: 'egress',
    severity: 'unknown',
    title: 'The run ended before this endpoint was checked',
    evidence: where(endpoint),
    remediation:
      'The global run budget expired before this endpoint got an answer, so nothing here is a ' +
      'verdict about the network. Re-run with a larger `--timeout`.',
  };
}

/**
 * Who owns a timeout, by the phase our own watchdog fired in.
 *
 * Silence on `connect` is a dropped SYN and a firewall conversation, but that
 * is one of four layers: a `getaddrinfo` that never returns is the resolver
 * (`src/net/endpoint.ts` gives the dns phase the connect budget, so a
 * black-hole resolver lands here), a handshake that hangs after a completed
 * connect is an inline appliance, and headers that never arrive are the
 * service. Sending all four to the network security team is the collapse
 * CLAUDE.md and ADR-0008 forbid - the ticket would be closed as "no drops
 * logged", correctly, and the operator would be no wiser.
 *
 * `phase` is one of our own literals, so it is also safe as `text` evidence
 * beside this text; nothing remote is interpolated into either.
 */
function timeoutRemediation(phase: AttemptPhase): string {
  switch (phase) {
    case 'dns':
      return (
        'The name lookup ran out of time before any packet was sent to this endpoint, so this is ' +
        'the resolver rather than the firewall. Ask the DNS team whether the resolver this ' +
        'machine uses serves this zone, and check whether a split-tunnel VPN is sending the ' +
        'query to one that never answers.'
      );
    case 'connect':
      return (
        'Silence rather than a refusal is the signature of a firewall dropping the packet. ' +
        'Request an outbound rule for this host and port, and cite the elapsed time above so ' +
        'the network team can match it against their own drop logs.'
      );
    case 'tls':
      return (
        'The connection opened and the TLS handshake then stalled part way, which a dropped ' +
        'packet cannot do - something in the path is holding the session open while it decides. ' +
        'That is what an inline inspection appliance looks like, so ask whoever owns TLS ' +
        'inspection here to check this destination.'
      );
    case 'http':
      return (
        'The connection and the handshake both completed and the response headers never ' +
        'arrived, so the request reached the endpoint or an intermediary in front of it and ' +
        'stopped there. This is not a blocked port: take the elapsed time above to whoever runs ' +
        'that service.'
      );
  }
}

function failed(endpoint: Endpoint, attempt: FailedAttempt): Finding {
  const evidence = where(endpoint);
  const code = attempt.code ?? NO_CODE;

  switch (classifyAttempt(attempt)) {
    case 'dns':
      return {
        id: 'egress.dns-failure',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        title: 'The endpoint hostname does not resolve from this machine',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Name resolution has to be fixed before anything else here means much. Ask the team ' +
          'that runs DNS or Active Directory whether this zone is served on this network, and ' +
          'check whether a split-tunnel VPN is sending the query to the wrong resolver.',
      };

    case 'refused':
      return {
        id: 'egress.connect-refused',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        title: 'The connection to the endpoint was refused',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Something on the path answered "no" rather than dropping the packet, which is what a ' +
          'firewall rule or a closed port looks like. Request an outbound rule for this host and ' +
          'port from the network security team, quoting the endpoint in the evidence above.',
      };

    case 'unreachable':
      return {
        id: 'egress.connect-unreachable',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        title: 'There is no route from this network to the endpoint',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'The packet had nowhere to go: this is routing or NAT, not a policy decision about the ' +
          'destination. Take it to the network team with the endpoint and code above, and check ' +
          'whether this machine is expected to reach the internet through a gateway at all.',
      };

    case 'timeout':
      return {
        id: 'egress.connect-timeout',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        // Phase-neutral on purpose: the watchdog fires at four layers, and on
        // the dns phase there is no connection yet to have timed out.
        title: 'The attempt to reach the endpoint timed out with no answer at all',
        evidence: [
          ...evidence,
          { label: 'phase', value: attempt.phase, kind: 'text' },
          { label: 'elapsed (ms)', value: String(totalMs(attempt.timing)), kind: 'number' },
        ],
        remediation: timeoutRemediation(attempt.phase),
      };

    case 'reset':
      return {
        id: 'egress.connection-reset',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        title: 'The connection to the endpoint was reset mid-flight',
        evidence: [...evidence, { label: 'phase', value: attempt.phase, kind: 'text' }],
        remediation:
          'A connection that opens and is then torn down is almost always an inline appliance - ' +
          'a next-generation firewall, a DLP box or a TLS-inspecting proxy - deciding it does not ' +
          'like this traffic. Ask whoever owns that appliance which rule fired at the phase above.',
      };

    case 'tls':
      return {
        id: 'egress.tls-failure',
        probe: 'egress',
        severity: cap('blocker', endpoint.required),
        title: 'The TLS handshake with the endpoint failed',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'The connection reached the endpoint and the handshake failed, which usually means TLS ' +
          'interception with a corporate root this machine does not trust, or a truststore that ' +
          'is missing the root entirely. The tls and truststore probes (M3/M4) name the root ' +
          'presented; until then, ask whether TLS inspection is enabled for this destination.',
      };

    case 'http':
      return httpError(endpoint, attempt.status);

    // `ok` cannot be produced for a failed attempt - `classifyAttempt` returns
    // it only when `attempt.ok` - but the compiler cannot see that, and
    // `unclassified` is the honest landing place for anything we cannot name.
    case 'ok':
    case 'unclassified':
      return {
        id: 'egress.unclassified',
        probe: 'egress',
        // Never capped: "we could not tell" does not get softer because the
        // endpoint is optional.
        severity: 'unknown',
        title: 'The connection failed in a way portcall does not recognise',
        evidence: [...evidence, { label: 'code', value: code, kind: 'text' }],
        remediation:
          'Portcall has no mapping for this failure, and guessing would send you to the wrong ' +
          'team. Send this report to the tool vendor: the code above plus the phase it happened ' +
          'in is enough for them to add the case.',
      };
  }
}
