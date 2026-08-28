import type { Probe, ProbeContext } from '../../engine/index.ts';
import type { Evidence, Finding } from '../../model/finding.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../../net/root-bundle.ts';
import { tlsCapturer } from '../../net/tls-capture.ts';
import type { TlsCapture, TlsCapturePhase, TlsCaptureTarget, TlsChainOutcome } from '../../net/types.ts';
import type { Endpoint } from '../../profiles/schema.ts';
import { certificateIndex } from '../shared/root-index.ts';
import { compareChains, evaluateChain } from './evaluate.ts';
import type { CapturedChain, ChainEvaluationOptions } from './evaluate.ts';
import { discoverEnvProxy } from './proxy-env.ts';

/**
 * The `tls` probe (M3, SPEC.md §7): what certificate chain does this machine
 * actually get from each endpoint, and does the chain change when the traffic
 * goes through the proxy this environment names.
 *
 * This file is the *edge*, and nothing else. It opens connections, and it turns
 * a capture that never happened into a finding; every judgement about a chain
 * belongs to `evaluate.ts`, which is pure over DER bytes (ADR-0002) and is
 * fixture-tested without a socket. The split is enforced, not merely intended:
 * `test/guardrails/x509-parse-only.test.ts` bans every `node:` import in this
 * directory, so the capture arrives through the `TlsCapture` seam and the
 * environment arrives as a parameter.
 *
 * Two captures per endpoint when the environment names a proxy, and the
 * comparison between them is the interception evidence that does not depend on
 * any trust judgement at all - two different certificates for one endpoint is
 * an observation about bytes.
 *
 * The seams arrive as default parameters, the same shape `main(argv, streams)`
 * and the other probes use.
 */

/** Per-phase budgets. A local copy, like the dns probe's: these bound their own question. */
const CONNECT_TIMEOUT_MS = 5000;
const TLS_TIMEOUT_MS = 5000;

/**
 * The one port that implies TLS without a scheme to say so, matching the egress
 * probe's rule. A profile endpoint on any other port is left alone: dialling a
 * handshake at a plaintext service would produce a certificate finding about a
 * question nobody asked, and portcall has no way to know that 8443 speaks TLS
 * until a profile says so.
 */
const TLS_PORT = 443;

/**
 * Stand-in for a failure that gave us no code and was not a timeout - a timeout
 * has its own id below, precisely so this stand-in is never the whole story.
 * Our string, not the network's.
 */
const NO_CODE = 'unavailable';

/** Which path a capture took. Also the value of the `connection` evidence on every finding below. */
type Path = 'direct' | 'proxy';

interface TlsTarget {
  host: string;
  port: number;
  /** True if *any* endpoint on this host and port is required: the strictest claim wins. */
  required: boolean;
}

export const tlsProbe: Probe = {
  name: 'tls',
  run(context: ProbeContext): Promise<Finding[]> {
    return runTls(context);
  },
};

export async function runTls(
  context: ProbeContext,
  capturer: TlsCapture = tlsCapturer,
  env: NodeJS.ProcessEnv = process.env,
  now: Date = new Date(),
): Promise<Finding[]> {
  const targets = tlsTargets(context.profile.profile.endpoints);
  if (targets.length === 0) return [];

  // Discovered once per run, not per endpoint: the variables cannot change
  // mid-run, and one proxy is the answer for every target (ADR-0023).
  const proxy = discoverEnvProxy(env);
  // Indexed once per run as well. The bundle is a few hundred certificates and
  // indexing it parses every one of them; doing that per endpoint would make a
  // ten-endpoint profile pay for it ten times.
  const options: ChainEvaluationOptions = { roots: certificateIndex(PUBLIC_ROOT_CA_PEMS), now };

  // Endpoints concurrently, for the reason the egress probe gives: a profile
  // behind a silent firewall would otherwise spend the whole run's budget
  // timing out on the first two.
  const findings = await Promise.all(
    targets.map((target) => checkTarget(target, context, capturer, proxy, options)),
  );
  return findings.flat();
}

/**
 * One capture per distinct host and port, not per endpoint. A profile that
 * lists the same host twice asks one TLS question, and capturing it twice
 * would put the same chain in the report twice.
 */
function tlsTargets(endpoints: readonly Endpoint[]): TlsTarget[] {
  const targets = new Map<string, TlsTarget>();
  for (const endpoint of endpoints) {
    if (endpoint.port !== TLS_PORT) continue;
    const key = `${endpoint.host}:${String(endpoint.port)}`;
    const existing = targets.get(key);
    if (existing === undefined) {
      targets.set(key, { host: endpoint.host, port: endpoint.port, required: endpoint.required });
      continue;
    }
    existing.required = existing.required || endpoint.required;
  }
  return [...targets.values()];
}

async function checkTarget(
  target: TlsTarget,
  context: ProbeContext,
  capturer: TlsCapture,
  proxy: { host: string; port: number } | null,
  options: ChainEvaluationOptions,
): Promise<Finding[]> {
  const capture = (via: TlsCaptureTarget['viaProxy']): Promise<TlsChainOutcome> =>
    capturer.capture(
      via === undefined ? { host: target.host, port: target.port } : { host: target.host, port: target.port, viaProxy: via },
      {
        signal: context.signal,
        guard: context.net,
        connectTimeoutMs: CONNECT_TIMEOUT_MS,
        tlsTimeoutMs: TLS_TIMEOUT_MS,
      },
    );

  const [direct, viaProxy] = await Promise.all([
    capture(undefined),
    proxy === null ? Promise.resolve(null) : capture(proxy),
  ]);

  const findings: Finding[] = [];
  const chains: Record<Path, CapturedChain | null> = { direct: null, proxy: null };

  for (const [path, outcome] of [
    ['direct', direct],
    ['proxy', viaProxy],
  ] as const) {
    if (outcome === null) continue;
    if (!outcome.ok) {
      findings.push(captureFailed(target, path, proxy, outcome));
      continue;
    }
    const chain: CapturedChain = {
      chainDer: outcome.chainDer,
      negotiatedProtocol: outcome.negotiatedProtocol,
      negotiatedCipher: outcome.negotiatedCipher,
      requestedSni: outcome.requestedSni,
      via: path,
    };
    chains[path] = chain;
    const evaluation = evaluateChain(chain, { host: target.host, required: target.required }, context.profile.profile, options);
    findings.push(...evaluation.findings);
    // The run's one mutation of the shared observation array (ADR-0034): one
    // push per path, so a host seen direct and through a proxy is two
    // observations, which is what the cross-check correlates on.
    if (evaluation.anchor !== null) context.observedAnchors.push(evaluation.anchor);
  }

  // Refuses to conclude anything when either side is missing - the failure that
  // took it away has already been reported just above.
  findings.push(...compareChains(chains.direct, chains.proxy, { host: target.host }));
  return findings;
}

/**
 * Where the capture was aimed. The proxy is named on the proxied path because
 * "which intermediary" is the first question a `tunnel` failure raises, and it
 * is `hostname` evidence rather than `public` - a corporate proxy's name is
 * the customer's, and the profile never named it.
 */
function where(target: TlsTarget, path: Path, proxy: { host: string; port: number } | null): Evidence[] {
  const evidence: Evidence[] = [
    { label: 'host', value: target.host, kind: 'hostname' },
    { label: 'port', value: String(target.port), kind: 'number' },
    { label: 'connection', value: path, kind: 'text' },
  ];
  if (path === 'proxy' && proxy !== null) evidence.push({ label: 'proxy', value: proxy.host, kind: 'hostname' });
  return evidence;
}

interface CaptureVerdict {
  id: string;
  title: string;
  remediation: string;
}

/**
 * What a capture that never produced a chain means, by the phase it died in.
 *
 * Every one is `unknown`, never `blocker`, and the reason is the one
 * `wpadUnusableFinding` gives in the proxy probe: this check could not decide,
 * and the reachability failure underneath it is already reported at `blocker`
 * by the dns or egress probe for the same host. Reporting it again as a
 * blocker would count one broken thing twice and make the summary lie about
 * how much is wrong.
 *
 * There is one `tunnel` id and not two. A 407 and a 403 are genuinely
 * different tickets - and the proxy probe already emits `proxy.auth-required`
 * and `proxy.connect-rejected` for the same proxy in the same run, at the
 * severity those deserve. Splitting them here would restate that probe's
 * verdict in a second vocabulary; the code on the evidence carries the
 * distinction for a reader who is looking at this finding alone.
 *
 * The `dns` and `connect` phases happen against the proxy on the proxied path -
 * `openTunnel` resolves and dials `viaProxy`, and the endpoint's own name is
 * never looked up there at all - so the `dns` and `connect` verdicts are each
 * written twice, once per path. The proxy is described rather than named: its hostname belongs on
 * the evidence, where redaction can reach it (ADR-0005), while a remediation
 * string crosses the report boundary verbatim.
 */
function captureVerdict(phase: TlsCapturePhase, path: Path): CaptureVerdict {
  switch (phase) {
    case 'dns':
      // Two zones and two tickets: on the proxied path the name that was
      // looked up is the proxy's, and the dns probe never resolves it.
      if (path === 'proxy') {
        return {
          id: 'tls.capture-failed-dns',
          title: 'The proxy name did not resolve, so no certificate chain could be captured',
          remediation:
            "Nothing in this report says anything about TLS for this endpoint: the proxy's own " +
            'name never resolved, so no handshake was attempted and the endpoint was never ' +
            "reached. The name that failed is the proxy's, named on the evidence above, and not " +
            "this endpoint's - which is also why the dns probe is silent about it, because that " +
            'probe resolves the names the profile declares and the profile never named this ' +
            'proxy. This is a DNS ticket rather than a certificate one, and the team that runs ' +
            "DNS or Active Directory owns it. Re-run once the proxy's name resolves.",
        };
      }
      return {
        id: 'tls.capture-failed-dns',
        title: 'The endpoint name did not resolve, so no certificate chain could be captured',
        remediation:
          'Nothing in this report says anything about TLS for this endpoint: the name never ' +
          'resolved, so no handshake was attempted. This is a DNS ticket rather than a ' +
          'certificate one - the dns probe reports the same failure for this host - and the team ' +
          'that runs DNS or Active Directory owns it. Re-run once the name resolves.',
      };
    case 'connect':
      // The same cross-probe claim fails here for the same reason: the egress
      // probe dials the profile's endpoints, and the proxy is not one of them.
      if (path === 'proxy') {
        return {
          id: 'tls.capture-failed-connect',
          title: 'The connection never opened, so no certificate chain could be captured',
          remediation:
            'The TCP connection to the endpoint (or to the proxy in front of it) never opened, ' +
            'so there was no handshake to observe and this is not a verdict about certificates. ' +
            'What did not open on this path is the connection to the proxy, named on the ' +
            "evidence above, and not the one to this endpoint's port - which is why the egress " +
            'probe is silent about it, because that probe dials the endpoints the profile ' +
            'declares and the profile never named this proxy. Take it to the network team as a ' +
            "route to the proxy, and re-run this check once the proxy's port is reachable.",
        };
      }
      return {
        id: 'tls.capture-failed-connect',
        title: 'The connection never opened, so no certificate chain could be captured',
        remediation:
          'The TCP connection to the endpoint (or to the proxy in front of it) never opened, so ' +
          'there was no handshake to observe and this is not a verdict about certificates. The ' +
          'egress probe reports the same failure with the layer that stopped it; take that to ' +
          'the network team, and re-run this check once the port is reachable.',
      };
    case 'tunnel':
      return {
        id: 'tls.capture-failed-tunnel',
        title: 'The proxy answered the CONNECT itself instead of opening a tunnel',
        remediation:
          'The proxy replied to the tunnel request rather than forwarding it, so no chain was ' +
          'captured through the proxied path. Portcall never authenticates - it reports the ' +
          'challenge a proxy makes and stops there (SPEC.md §4) - so an HTTP_407 code above ' +
          'means the tunnel wants credentials this tool will not supply, and an HTTP_403 means ' +
          'policy declined it. Take the code to the proxy team; the proxy probe names the ' +
          'authentication scheme demanded, and this check reports the chain once a tunnel opens.',
      };
    case 'tls':
      return {
        id: 'tls.capture-failed-tls',
        title: 'The handshake failed before any certificate was presented',
        remediation:
          'The connection opened and the handshake died before the peer sent a chain, so there ' +
          'is nothing to judge - portcall deliberately accepts any certificate at this point, so ' +
          'this is not a trust failure. A handshake that is torn down rather than completed is ' +
          'what an inline inspection appliance looks like; ask whoever owns TLS inspection here ' +
          'to check this destination, quoting the code above.',
      };
  }
}

/**
 * Who owns a capture that ran out of time, by the phase our own watchdog fired
 * in. Silence has no code to report, so the phase is the whole of what we
 * know - and the four phases are four different owners, which is why this is
 * its own id rather than the coded finding above wearing an `unavailable`
 * stand-in where a real code belongs.
 *
 * `phase` is one of our own literals, so it is safe as `text` evidence beside
 * this text; nothing remote is interpolated into either - including the proxy,
 * which the two proxied-path branches point at without spelling its name, for
 * the redaction reason `captureVerdict` gives above.
 */
function timeoutRemediation(phase: TlsCapturePhase, path: Path): string {
  switch (phase) {
    case 'dns':
      if (path === 'proxy') {
        return (
          'The name lookup ran out of time before any packet reached the proxy, so no handshake ' +
          'was attempted and this is not a verdict about certificates. The name that never ' +
          "resolved is the proxy's, named on the evidence above, and not this endpoint's - on a " +
          'proxied path this machine looks up the proxy and the proxy looks up the endpoint. A ' +
          'resolver that never answers is a DNS ticket rather than a firewall one: ask the DNS ' +
          "team whether the resolver this machine uses serves the proxy's zone, and whether a " +
          'split-tunnel VPN is sending the query somewhere that will not.'
        );
      }
      return (
        'The name lookup ran out of time before any packet reached this endpoint, so no ' +
        'handshake was attempted and this is not a verdict about certificates. A resolver that ' +
        'never answers is a DNS ticket rather than a firewall one: ask the DNS team whether the ' +
        'resolver this machine uses serves this zone, and whether a split-tunnel VPN is sending ' +
        'the query somewhere that will not.'
      );
    case 'connect':
      if (path === 'proxy') {
        return (
          'The connection never opened and nothing refused it, and silence rather than a refusal ' +
          'is the signature of a firewall dropping the packet. What never answered is the proxy, ' +
          'named on the evidence above, and not this endpoint - on a proxied path this machine ' +
          "connects only to the proxy, and the endpoint's own port is dialled from there. There " +
          'was no handshake to observe, so this is not a verdict about certificates - ask the ' +
          'network team for an outbound rule to the proxy rather than to this host and port, ' +
          'and re-run once the proxy answers.'
        );
      }
      return (
        'The connection never opened and nothing refused it, and silence rather than a refusal ' +
        'is the signature of a firewall dropping the packet. There was no handshake to observe, ' +
        'so this is not a verdict about certificates - request an outbound rule for this host ' +
        'and port from the network team, and re-run once the port answers.'
      );
    case 'tunnel':
      return (
        'The proxy accepted the TCP connection and then never answered the CONNECT at all. That ' +
        'is not `tls.capture-failed-tunnel`, where the proxy replies and the reply is the ' +
        'answer: here there was no reply to read, so there is no status code to quote and ' +
        'nothing was learned about certificates. Ask the proxy team what becomes of a tunnel ' +
        'request for this destination.'
      );
    case 'tls':
      return (
        'The connection opened and the handshake then stalled part way, which a dropped packet ' +
        'cannot do - something in the path is holding the session open while it decides. No ' +
        'certificate arrived, so this is not a trust failure; it is what an inline inspection ' +
        'appliance looks like. Ask whoever owns TLS inspection here to check this destination.'
      );
  }
}

function captureFailed(
  target: TlsTarget,
  path: Path,
  proxy: { host: string; port: number } | null,
  outcome: Extract<TlsChainOutcome, { ok: false }>,
): Finding {
  // Checked before the phase is read: a cancelled run taught us nothing about
  // this endpoint, and every verdict below would be a claim about the network.
  if (outcome.abortedBy === 'run-signal') return aborted(target, path, proxy);
  // Before the coded verdict, because a timeout has no code: `NO_CODE` below
  // would report our own stand-in where a reader expects the network's word.
  if (outcome.abortedBy === 'phase-timeout') return timedOut(target, path, proxy, outcome.phase);

  const { id, title, remediation } = captureVerdict(outcome.phase, path);
  return {
    id,
    probe: 'tls',
    // Never capped by `required`: "we could not tell" does not get softer or
    // sharper because the endpoint is optional.
    severity: 'unknown',
    title,
    evidence: [...where(target, path, proxy), { label: 'code', value: outcome.code ?? NO_CODE, kind: 'text' }],
    remediation,
  };
}

function timedOut(
  target: TlsTarget,
  path: Path,
  proxy: { host: string; port: number } | null,
  phase: TlsCapturePhase,
): Finding {
  return {
    id: 'tls.capture-failed-timeout',
    probe: 'tls',
    // `unknown` and never capped by `required`, for the reason `captureVerdict`
    // gives above: the reachability failure underneath is already a blocker
    // somewhere else in this report.
    severity: 'unknown',
    title: 'The attempt to capture a certificate chain timed out with no answer at all',
    // No `code` evidence: the transport had none to give, and that silence is
    // the finding.
    evidence: [...where(target, path, proxy), { label: 'phase', value: phase, kind: 'text' }],
    remediation: timeoutRemediation(phase, path),
  };
}

function aborted(target: TlsTarget, path: Path, proxy: { host: string; port: number } | null): Finding {
  return {
    id: 'tls.aborted',
    probe: 'tls',
    severity: 'unknown',
    title: 'The run ended before this certificate chain was captured',
    evidence: where(target, path, proxy),
    remediation:
      'The global run budget expired before the handshake finished, so this is not a verdict ' +
      'about the network or about the certificate this endpoint presents. Re-run with a larger ' +
      '`--timeout`.',
  };
}
