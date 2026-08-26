import { SubjectAlternativeNameExtension, X509Certificate } from '@peculiar/x509';
import type { Evidence, Finding } from '../../model/finding.ts';
import type { Profile } from '../../profiles/schema.ts';
import { cap } from '../shared/severity.ts';
import { classifyRoot } from './public-roots.ts';
import type { PublicRootIndex, RootVerdict } from './public-roots.ts';

/**
 * TLS chain evaluation (M3, SPEC.md 7, ADR-0002).
 *
 * Pure: DER bytes in, findings out. No socket, no trust store, no clock - the
 * capture happens in `src/net/tls-capture.ts` and `now` is injected below - so
 * every verdict in this file is reproducible from bytes a test can hold, which
 * is the whole point of splitting the probe this way.
 *
 * `@peculiar/x509` is used strictly to parse and to read fields (ADR-0021).
 * `X509ChainBuilder`, `cert.verify()` and every other trust-shaped API are out
 * of bounds, and `test/guardrails/x509-parse-only.test.ts` enforces that rather
 * than trusting this comment. The consequence is deliberate: root membership is
 * decided in exactly one place, `public-roots.ts`, over the runtime's own
 * bundle, and the answers this file gives are only ever as strong as the bytes
 * support.
 *
 * The findings are split by *ticket*, not by layer (CLAUDE.md): a private root
 * goes to whoever runs the interception appliance, an expired certificate to
 * whoever owns the certificate, a name mismatch to whoever issued it, and a
 * protocol below the profile floor to whoever configured the terminator. They
 * are four different conversations and never one `tls.broken`.
 */

/**
 * How far ahead of expiry a certificate is worth reporting.
 *
 * The profile schema carries no expiry policy (`src/profiles/schema.ts` has
 * `tls.min_version` and `tls.interception_tolerated`, and nothing else), so
 * this is a constant here rather than profile-driven - adding a knob to the
 * schema is a decision for a profile that actually needs one, not something to
 * invent on the way past. Thirty days is one monthly change window: an
 * operator who reads this report has one change-management cycle to renew
 * before it becomes an outage, which is the shortest warning that is still
 * actionable inside a large organisation.
 */
export const EXPIRY_WARNING_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;

/** How many SAN entries a finding will list before it stops. A CDN certificate can carry hundreds. */
const MAX_SAN_EVIDENCE = 8;

/**
 * One captured chain, as `src/net/tls-capture.ts` observed it, plus which path
 * it came over. `via` is the caller's own knowledge, not the peer's.
 */
export interface CapturedChain {
  /** Leaf first, one DER-encoded certificate per element, exactly as presented. */
  chainDer: readonly Uint8Array[];
  negotiatedProtocol: string | null;
  negotiatedCipher: string | null;
  /** The SNI actually sent; the empty string when the target was a literal address. */
  requestedSni: string;
  via: 'direct' | 'proxy';
}

/** The endpoint this chain was captured for. `required` caps severity, as everywhere else. */
export interface ChainTarget {
  host: string;
  required: boolean;
}

/**
 * The two things the evaluation needs that are neither the capture nor the
 * profile. Bundled into one named bag rather than trailing as two positional
 * parameters, following `AttemptOptions`' precedent in `src/net/types.ts`.
 */
export interface ChainEvaluationOptions {
  /** The runtime's public root bundle, indexed. Passed in so this module imports no `node:*`. */
  roots: PublicRootIndex;
  /** Evaluation time. Injected so expiry is a function of its inputs and not of the day the suite runs. */
  now: Date;
}

/** Protocol names ranked by strength. Anything outside this table is a name we will not repeat. */
const PROTOCOL_RANK: Readonly<Record<string, number>> = {
  SSLv3: 0,
  TLSv1: 1,
  'TLSv1.1': 2,
  'TLSv1.2': 3,
  'TLSv1.3': 4,
};

/** The profile's floor, on the same scale. */
const MIN_VERSION_RANK: Readonly<Record<Profile['tls']['min_version'], number>> = {
  '1.0': 1,
  '1.1': 2,
  '1.2': 3,
  '1.3': 4,
};

function host(name: string): Evidence {
  return { label: 'host', value: name, kind: 'hostname' };
}

function via(capture: CapturedChain): Evidence {
  return { label: 'connection', value: capture.via, kind: 'text' };
}

function subject(certificate: X509Certificate): Evidence {
  return { label: 'subject', value: certificate.subject, kind: 'dn' };
}

function issuer(certificate: X509Certificate, label = 'issuer'): Evidence {
  return { label, value: certificate.issuer, kind: 'dn' };
}

function serial(certificate: X509Certificate): Evidence {
  return { label: 'serial', value: certificate.serialNumber, kind: 'serial' };
}

function count(label: string, value: number): Evidence {
  return { label, value: String(value), kind: 'number' };
}

/**
 * Parse the whole chain, or nothing.
 *
 * A chain with one unreadable certificate in it is not a chain we can reason
 * about: the anchor might be the broken one. Reporting that honestly beats
 * evaluating the readable prefix and implying the rest agreed.
 */
function parseChain(chainDer: readonly Uint8Array[]): X509Certificate[] | null {
  const chain: X509Certificate[] = [];
  for (const der of chainDer) {
    try {
      chain.push(new X509Certificate(der));
    } catch {
      return null;
    }
  }
  return chain;
}

/** Parse one certificate, for the paths where a failure is not itself the finding. */
function parseOne(der: Uint8Array | undefined): X509Certificate | null {
  if (der === undefined) return null;
  try {
    return new X509Certificate(der);
  } catch {
    return null;
  }
}

/** dNSName SAN entries, or `null` when the certificate carries no SAN extension at all. */
function dnsNames(certificate: X509Certificate): string[] | null {
  const extension = certificate.getExtension('2.5.29.17');
  if (!(extension instanceof SubjectAlternativeNameExtension)) return null;
  return extension.names.items.filter((name) => name.type === 'dns').map((name) => name.value);
}

/**
 * RFC 6125 name matching, in the shape every mainstream TLS client implements
 * it rather than the shape the RFC permits:
 *
 * - the wildcard may only be the *whole* leftmost label, so `f*.example.com`
 *   matches nothing (browsers and `node:tls` both dropped partial wildcards);
 * - it covers exactly one label, so `*.example.com` matches `api.example.com`
 *   and not `a.b.example.com` and not the bare `example.com`;
 * - `*.com` matches nothing, because a wildcard directly under a public suffix
 *   is not a certificate anybody should honour.
 *
 * Matching the CN is deliberately not implemented. CN-as-hostname has been
 * dead in every client that matters for years, so a certificate that only
 * carries a name in its CN *will* be rejected in production - reporting it as
 * a match here would hide the very failure the operator is about to hit.
 */
export function matchesDnsName(name: string, pattern: string): boolean {
  const candidate = name.toLowerCase().replace(/\.$/, '');
  const wanted = pattern.toLowerCase().replace(/\.$/, '');
  if (candidate === '' || wanted === '') return false;

  if (!wanted.startsWith('*.')) return wanted.indexOf('*') === -1 && candidate === wanted;

  const suffix = wanted.slice(1);
  if (suffix.indexOf('*') !== -1) return false;
  // `.example.com` -> `example.com` must still contain a dot.
  if (!suffix.slice(1).includes('.')) return false;

  const firstDot = candidate.indexOf('.');
  if (firstDot <= 0) return false;
  return candidate.slice(firstDot) === suffix;
}

/** Whole days from `now` to `notAfter`, rounded down: a certificate is not "expiring in 1 day" all day. */
function daysUntil(deadline: Date, now: Date): number {
  return Math.floor((deadline.getTime() - now.getTime()) / DAY_MS);
}

function chainEmpty(target: ChainTarget, capture: CapturedChain): Finding {
  return {
    id: 'tls.chain-empty',
    probe: 'tls',
    severity: 'unknown',
    title: 'The handshake completed without a certificate being presented',
    evidence: [host(target.host), via(capture)],
    remediation:
      'Nothing can be said about TLS on this endpoint: the peer completed a handshake and sent ' +
      'no certificate chain, which no ordinary HTTPS server does. Confirm with the team that ' +
      'owns this address that the port really terminates TLS, and re-run; if it repeats, capture ' +
      'the handshake with `openssl s_client -connect host:port -showcerts` and hand that to them.',
  };
}

function chainUnparseable(target: ChainTarget, capture: CapturedChain, length: number): Finding {
  return {
    id: 'tls.chain-unparseable',
    probe: 'tls',
    severity: 'unknown',
    title: 'The presented certificate chain could not be parsed',
    evidence: [host(target.host), via(capture), count('certificates presented', length)],
    remediation:
      'The peer presented bytes that are not a readable X.509 chain, so this is not a verdict ' +
      'about trust either way. Capture the chain with `openssl s_client -connect host:port ' +
      '-showcerts` and give it to whoever operates the TLS terminator on this network - a ' +
      'middlebox emitting malformed certificates will break every client, not just this one.',
  };
}

function publicRoot(target: ChainTarget, capture: CapturedChain, root: X509Certificate, roots: PublicRootIndex): Finding {
  return {
    id: 'tls.public-root',
    probe: 'tls',
    severity: 'ok',
    title: 'The certificate chain anchors in a public root the runtime ships',
    evidence: [
      host(target.host),
      via(capture),
      // The name of a matched public root is already public knowledge - it is
      // in every browser on earth - so it is emitted verbatim, unlike the
      // private-root case below.
      { label: 'root', value: root.subject, kind: 'public' },
      count('roots in bundle', roots.size),
    ],
  };
}

/**
 * The certificate the verdict was reached about: the last one on the leaf's
 * issuance path. `verdict.path` is never empty and always indexes the chain it
 * was computed from, so the guard is for the compiler.
 */
function anchorOf(chain: readonly X509Certificate[], verdict: RootVerdict): X509Certificate {
  const index = verdict.path.at(-1);
  const anchor = index === undefined ? undefined : chain[index];
  /* c8 ignore next */
  if (anchor === undefined) throw new Error('a root verdict always names a certificate on the chain');
  return anchor;
}

function privateRoot(
  target: ChainTarget,
  capture: CapturedChain,
  chain: readonly X509Certificate[],
  verdict: RootVerdict,
  profile: Pick<Profile, 'tls'>,
): Finding {
  // The anchor is the end of the leaf's issuance path, not the end of the
  // array: a chain can carry certificates the leaf never leads to, and naming
  // one of those as the root would describe a certificate that is not in this
  // chain at all.
  const top = anchorOf(chain, verdict);
  const leaf = chain[0];
  const tolerated = profile.tls.interception_tolerated;

  const evidence: Evidence[] = [host(target.host), via(capture), { label: 'reason', value: verdict.reason, kind: 'text' }];
  evidence.push(subject(top), issuer(top, 'root issuer'));
  if (leaf !== undefined) evidence.push(serial(leaf));
  evidence.push(count('certificates presented', chain.length), count('certificates on issuance path', verdict.path.length));

  return {
    id: 'tls.private-root',
    probe: 'tls',
    // A profile that tolerates interception has already accepted that TLS is
    // terminated locally; what is left is a configuration job, so it degrades
    // rather than blocks. A profile that does not is stating that the vendor's
    // client will refuse this chain, which is a blocker - capped, as ever, by
    // whether the endpoint is required.
    severity: tolerated ? 'degraded' : cap('blocker', target.required),
    title: 'TLS is terminated by a certificate authority the runtime does not ship',
    evidence,
    remediation: tolerated
      ? 'This network re-signs TLS with its own certificate authority, which this profile ' +
        'expects. Every runtime still has to be told to trust it: export the CA in PEM form from ' +
        'whoever runs the proxy, then point the tool at it (`NODE_EXTRA_CA_CERTS` for Node, ' +
        '`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` for Python, the system store for Go). Installing it ' +
        'in the OS store alone is not enough for runtimes that ship their own bundle.'
      : 'This network re-signs TLS with its own certificate authority, and this profile says the ' +
        'client will not accept that - certificate pinning and mutual TLS both break under ' +
        'interception no matter which roots are installed. Ask the team that runs the ' +
        'inspection appliance for a decryption bypass for the hosts in this profile; that is a ' +
        'routine, per-destination policy change and does not require turning inspection off.',
  };
}

function rootIndeterminate(
  target: ChainTarget,
  capture: CapturedChain,
  chain: readonly X509Certificate[],
  verdict: RootVerdict,
): Finding {
  const top = anchorOf(chain, verdict);
  const evidence: Evidence[] = [host(target.host), via(capture), { label: 'reason', value: verdict.reason, kind: 'text' }];
  evidence.push(issuer(top, 'names as issuer'));
  evidence.push(count('certificates presented', chain.length), count('certificates on issuance path', verdict.path.length));

  return {
    id: 'tls.root-indeterminate',
    probe: 'tls',
    severity: 'unknown',
    title: 'The chain does not carry its root, so the anchor could not be identified',
    evidence,
    remediation:
      'The peer sent an incomplete chain: it names an issuer that exists in the public bundle ' +
      'but did not present it, and portcall does not verify signatures, so it will not claim the ' +
      'chain is public on the strength of a name (ADR-0021). Ask whoever operates this endpoint ' +
      'to serve the full chain including intermediates - clients that lack the missing ' +
      'certificate will fail here for the same reason.',
  };
}

function protocolFindings(
  target: ChainTarget,
  capture: CapturedChain,
  profile: Pick<Profile, 'tls'>,
): Finding[] {
  const { negotiatedProtocol } = capture;
  const rank = negotiatedProtocol === null ? undefined : PROTOCOL_RANK[negotiatedProtocol];
  const floor = MIN_VERSION_RANK[profile.tls.min_version];

  if (rank === undefined) {
    return [
      {
        id: 'tls.protocol-unknown',
        probe: 'tls',
        severity: 'unknown',
        title: 'The negotiated TLS version could not be identified',
        // The name itself is deliberately not reported: it is a string the peer
        // (or a middlebox) chose, and `text` evidence crosses the redaction
        // boundary unhashed (`test/guardrails/probe-evidence-kinds.test.ts`).
        evidence: [host(target.host), via(capture)],
        remediation:
          'The handshake completed but reported a protocol name this tool does not recognise, so ' +
          'it cannot be checked against the profile minimum. Re-run on a current release; if it ' +
          'persists, run `openssl s_client -connect host:port` and check what the terminator on ' +
          'this path is actually negotiating.',
      },
    ];
  }

  if (rank >= floor) {
    return [
      {
        id: 'tls.protocol',
        probe: 'tls',
        severity: 'ok',
        title: 'The negotiated TLS version meets the profile minimum',
        evidence: [
          host(target.host),
          via(capture),
          { label: 'protocol', value: negotiatedProtocol ?? '', kind: 'text' },
        ],
      },
    ];
  }

  return [
    {
      id: 'tls.protocol-below-minimum',
      probe: 'tls',
      severity: cap('blocker', target.required),
      title: 'The negotiated TLS version is below the minimum this profile requires',
      evidence: [
        host(target.host),
        via(capture),
        { label: 'protocol', value: negotiatedProtocol ?? '', kind: 'text' },
        { label: 'profile minimum', value: profile.tls.min_version, kind: 'text' },
      ],
      remediation:
        'The client will refuse this connection even though the handshake succeeded here, ' +
        'because it requires a newer TLS version than this path offers. Ask the team that runs ' +
        'the TLS-terminating appliance to enable the profile minimum for these hosts; an ' +
        'appliance downgrading traffic to an old TLS version is usually a legacy compatibility ' +
        'setting rather than an intentional policy.',
    },
  ];
}

interface ValidityWindow {
  certificate: X509Certificate;
  index: number;
}

/** The certificate that expires first: a chain is only valid for as long as its shortest-lived member. */
function earliestExpiring(chain: readonly X509Certificate[]): ValidityWindow | null {
  let earliest: ValidityWindow | null = null;
  for (const [index, certificate] of chain.entries()) {
    if (earliest === null || certificate.notAfter.getTime() < earliest.certificate.notAfter.getTime()) {
      earliest = { certificate, index };
    }
  }
  return earliest;
}

/** The certificate whose start date is furthest in the future, if any is not valid yet. */
function notYetValid(chain: readonly X509Certificate[], now: Date): ValidityWindow | null {
  let latest: ValidityWindow | null = null;
  for (const [index, certificate] of chain.entries()) {
    if (certificate.notBefore.getTime() <= now.getTime()) continue;
    if (latest === null || certificate.notBefore.getTime() > latest.certificate.notBefore.getTime()) {
      latest = { certificate, index };
    }
  }
  return latest;
}

function validityFindings(
  target: ChainTarget,
  capture: CapturedChain,
  chain: readonly X509Certificate[],
  now: Date,
): Finding[] {
  const findings: Finding[] = [];

  const early = notYetValid(chain, now);
  if (early !== null) {
    findings.push({
      id: 'tls.chain-not-yet-valid',
      probe: 'tls',
      severity: cap('blocker', target.required),
      title: 'A certificate in the chain is not valid yet',
      evidence: [
        host(target.host),
        via(capture),
        subject(early.certificate),
        count('chain position', early.index),
        count('days until it becomes valid', daysUntil(early.certificate.notBefore, now)),
      ],
      remediation:
        "This is a clock problem far more often than a certificate problem: check this machine's " +
        'time and timezone against a reliable source first, since a skewed clock breaks every TLS ' +
        'client on the host. If the clock is right, the certificate was issued with a future ' +
        'start date and whoever issued it has to re-issue it.',
    });
  }

  const earliest = earliestExpiring(chain);
  if (earliest === null) return findings;

  const remaining = daysUntil(earliest.certificate.notAfter, now);
  if (earliest.certificate.notAfter.getTime() <= now.getTime()) {
    findings.push({
      id: 'tls.chain-expired',
      probe: 'tls',
      severity: cap('blocker', target.required),
      title: 'A certificate in the chain has expired',
      evidence: [
        host(target.host),
        via(capture),
        subject(earliest.certificate),
        count('chain position', earliest.index),
        count('days since it expired', -remaining),
      ],
      remediation:
        'Every client that checks certificates is already failing on this endpoint. Send the ' +
        'subject in the evidence above to whoever owns that certificate and have it renewed. If ' +
        'the expired certificate is an interception CA rather than the origin, it belongs to ' +
        'whoever runs the proxy, and renewing it will require re-distributing the new CA.',
    });
    return findings;
  }

  if (remaining <= EXPIRY_WARNING_DAYS) {
    findings.push({
      id: 'tls.chain-expiring-soon',
      probe: 'tls',
      severity: 'degraded',
      title: 'A certificate in the chain expires within the warning window',
      evidence: [
        host(target.host),
        via(capture),
        subject(earliest.certificate),
        count('chain position', earliest.index),
        count('days until expiry', remaining),
        count('warning window (days)', EXPIRY_WARNING_DAYS),
      ],
      remediation:
        'Nothing is broken yet, and this is the last comfortable moment to fix it. Raise the ' +
        'renewal with whoever owns the certificate named above now: after it expires every ' +
        'client on this path fails at once, and a change window inside a large organisation is ' +
        'rarely shorter than the time left.',
    });
  }

  return findings;
}

function nameFindings(
  target: ChainTarget,
  capture: CapturedChain,
  leaf: X509Certificate,
): Finding[] {
  // No SNI was sent, so the target was a literal address and there is no name
  // to judge the certificate against. Saying anything here would be inventing
  // the question as well as the answer.
  if (capture.requestedSni === '') return [];

  const names = dnsNames(leaf);
  if (names === null) {
    return [
      {
        id: 'tls.leaf-no-san',
        probe: 'tls',
        severity: cap('blocker', target.required),
        title: 'The leaf certificate carries no subject alternative name',
        evidence: [
          host(target.host),
          via(capture),
          { label: 'requested name', value: capture.requestedSni, kind: 'hostname' },
          subject(leaf),
          issuer(leaf),
        ],
        remediation:
          'Modern TLS clients ignore the common name entirely and will reject this certificate ' +
          'outright, whatever its CN says. Ask whoever issued it - the origin team, or whoever ' +
          'runs the interception appliance if the chain is privately rooted - to re-issue with a ' +
          'subjectAltName covering the hostname in the evidence above.',
      },
    ];
  }

  if (names.some((name) => matchesDnsName(capture.requestedSni, name))) return [];

  const listed = names.slice(0, MAX_SAN_EVIDENCE);
  return [
    {
      id: 'tls.sni-mismatch',
      probe: 'tls',
      severity: cap('blocker', target.required),
      title: 'The presented certificate does not cover the name that was requested',
      evidence: [
        host(target.host),
        via(capture),
        { label: 'requested name', value: capture.requestedSni, kind: 'hostname' },
        ...listed.map((name): Evidence => ({ label: 'certificate name', value: name, kind: 'hostname' })),
        count('names on certificate', names.length),
        subject(leaf),
      ],
      remediation:
        'Every client will reject this connection with a hostname-verification error. If the ' +
        'chain is publicly rooted, the endpoint is serving the wrong certificate and its owner ' +
        'has to fix the binding; if it is privately rooted, the interception appliance is ' +
        'generating certificates for the wrong name - usually because it is keying off the ' +
        'address rather than the SNI - and that is a proxy configuration ticket.',
    },
  ];
}

/**
 * Evaluate one captured chain.
 *
 * Deviation from the M3 plan, flagged deliberately: the contract read
 * `evaluateChain(capture, target, profile)`, and this takes a fourth
 * `ChainEvaluationOptions`. Both members of it have to come from outside - the
 * root bundle because importing it here would drag `node:tls` into a module
 * that must stay pure, and `now` because a pure function may not read the
 * clock. The semantics are unchanged.
 */
export function evaluateChain(
  capture: CapturedChain,
  target: ChainTarget,
  profile: Pick<Profile, 'tls'>,
  options: ChainEvaluationOptions,
): Finding[] {
  if (capture.chainDer.length === 0) return [chainEmpty(target, capture)];

  const chain = parseChain(capture.chainDer);
  if (chain === null) return [chainUnparseable(target, capture, capture.chainDer.length)];

  const leaf = chain[0];
  /* c8 ignore next */
  if (leaf === undefined) return [chainEmpty(target, capture)];

  const verdict = classifyRoot(chain, options.roots);
  const findings: Finding[] = [];

  switch (verdict.class) {
    case 'public': {
      const matched = verdict.matchedIndex === null ? undefined : chain[verdict.matchedIndex];
      // `matchedIndex` always indexes the chain that produced it; the guard is
      // for the compiler, not for a case that can happen.
      /* c8 ignore next */
      if (matched !== undefined) findings.push(publicRoot(target, capture, matched, options.roots));
      break;
    }
    case 'private':
      findings.push(privateRoot(target, capture, chain, verdict, profile));
      break;
    case 'indeterminate':
      findings.push(rootIndeterminate(target, capture, chain, verdict));
      break;
  }

  findings.push(...protocolFindings(target, capture, profile));
  findings.push(...validityFindings(target, capture, chain, options.now));
  findings.push(...nameFindings(target, capture, leaf));

  return findings;
}

function interceptionEvidence(label: string, capture: CapturedChain): Evidence[] {
  const leaf = parseOne(capture.chainDer[0]);
  const evidence: Evidence[] = [count(`${label} chain length`, capture.chainDer.length)];
  if (leaf !== null) evidence.push({ label: `${label} leaf issuer`, value: leaf.issuer, kind: 'dn' });
  return evidence;
}

/**
 * Compare the chain seen directly against the chain seen through the proxy.
 *
 * What this can conclude, and what it refuses to:
 *
 * - **Both chains present, different leaf bytes.** Something on the proxied
 *   path re-issued the certificate. That is interception, and it is the one
 *   claim here that does not depend on any trust judgement at all - two
 *   different certificates for one endpoint is an observation about bytes.
 * - **Both chains present, identical leaf bytes.** The proxy forwarded the
 *   handshake untouched. Note the narrowness: it says the proxy did not
 *   re-sign, *not* that the endpoint is safe, and not that neither path is
 *   intercepted - a transparent appliance sitting in front of both paths would
 *   produce two identical, privately rooted chains. `tls.private-root` from
 *   `evaluateChain` is what reports that, on each path separately.
 * - **Either side missing.** Nothing. A capture that failed is not evidence
 *   that the two paths agree or disagree, and the shell already reports why the
 *   missing side failed (`tls.capture-failed-*`). An `unknown` finding here
 *   would be a second, emptier copy of that one.
 *
 * Severity is fixed rather than profile-driven because the comparison has no
 * profile: `interception_tolerated` is applied where the trust verdict is made,
 * in `evaluateChain`. This finding reports the fact and stays `degraded` so it
 * cannot silently escalate a tolerated setup into a blocker.
 */
export function compareChains(
  direct: CapturedChain | null,
  viaProxy: CapturedChain | null,
  target: { host: string },
): Finding[] {
  if (direct === null || viaProxy === null) return [];

  const directLeaf = direct.chainDer[0];
  const proxyLeaf = viaProxy.chainDer[0];
  // An empty chain on either side is `tls.chain-empty`'s business, not this
  // comparison's: there is nothing to compare, and "different" would be a lie.
  if (directLeaf === undefined || proxyLeaf === undefined) return [];

  const identical =
    directLeaf.length === proxyLeaf.length && directLeaf.every((byte, index) => byte === proxyLeaf[index]);

  if (identical) {
    return [
      {
        id: 'tls.chain-consistent',
        probe: 'tls',
        severity: 'ok',
        title: 'The proxied path presents the same certificate as the direct path',
        evidence: [host(target.host), ...interceptionEvidence('direct', direct)],
      },
    ];
  }

  return [
    {
      id: 'tls.intercepted-via-proxy',
      probe: 'tls',
      severity: 'degraded',
      title: 'The proxy presents a different certificate than the endpoint does directly',
      evidence: [
        host(target.host),
        ...interceptionEvidence('direct', direct),
        ...interceptionEvidence('proxied', viaProxy),
      ],
      remediation:
        'The proxy is decrypting and re-signing traffic to this endpoint rather than forwarding ' +
        'it. Every runtime on this machine has to trust the appliance CA for that to work, and ' +
        'anything that pins a certificate or uses mutual TLS will fail regardless. Take the ' +
        'issuer in the evidence above to whoever runs the proxy and agree one of two things: ' +
        'distribute the CA to the runtimes this tool uses, or add a decryption bypass for the ' +
        'hosts in this profile.',
    },
  ];
}
