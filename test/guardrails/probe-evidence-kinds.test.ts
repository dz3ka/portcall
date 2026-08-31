import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { NetworkGuard, NetworkPolicyError } from '../../src/net/guard.ts';
import { extractCode } from '../../src/net/dns.ts';
import type { AttemptPhase, DnsOutcome, DnsResolver, EndpointAttempt, EndpointProber } from '../../src/net/types.ts';
import type { ObservedAnchor, ProbeContext } from '../../src/engine/index.ts';
import type { ProbeErrorClass } from '../../src/engine/probe-error.ts';
import { probeErrorFinding } from '../../src/engine/probe-error.ts';
import type { Evidence, Finding } from '../../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../../src/profiles/schema.ts';
import type { AddressClass } from '../../src/probes/dns/analyse.ts';
import type { DohOutcome, ResolveFailure } from '../../src/probes/dns/index.ts';
import { runDns } from '../../src/probes/dns/index.ts';
import { runEgress } from '../../src/probes/egress/index.ts';
import type { ProxyConnectDetail } from '../../src/net/proxy-connect.ts';
import type { AuthScheme, PacFetchOutcome, PacFetcher } from '../../src/net/types.ts';
import type { PacVerdict } from '../../src/probes/proxy/pac.ts';
import type { NoProxyEntryIssue } from '../../src/probes/proxy/no-proxy.ts';
import { runProxy } from '../../src/probes/proxy/index.ts';
import { TLS_VERSIONS } from '../../src/profiles/schema.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../../src/net/root-bundle.ts';
import type { TlsCapture, TlsCapturePhase, TlsChainOutcome } from '../../src/net/types.ts';
import { compareChains, evaluateChain } from '../../src/probes/tls/evaluate.ts';
import type { CapturedChain } from '../../src/probes/tls/evaluate.ts';
import { runTls } from '../../src/probes/tls/index.ts';
import { certificateIndex } from '../../src/probes/shared/root-index.ts';
import { crossCheck } from '../../src/probes/truststore/evaluate.ts';
import { OS_TRUSTSTORE_COMMANDS } from '../../src/net/os-truststore.ts';
import { derToPem } from '../../src/net/pem.ts';
import type {
  RuntimeStoreFailure,
  RuntimeStoreKind,
  RuntimeStoreOutcome,
  TrustStoreFailure,
  TrustStoreKind,
  TrustStoreOutcome,
} from '../../src/net/types.ts';
import type { RootReason } from '../../src/probes/tls/public-roots.ts';
import { derOfPem, subjectOfPem, syntheticCert, syntheticChain } from '../helpers/synthetic-chain.ts';

/**
 * SPEC.md 4.5 / ADR-0005: `text` evidence crosses the redaction boundary
 * *unhashed* (`src/redact/index.ts` hashes only the identifier kinds), so a
 * string that came from the network - a server header, a certificate subject,
 * a resolver's error prose, a TLS protocol name we do not recognise - reaching
 * `text` evidence would put peer-controlled content straight into a report the
 * customer forwards to a vendor. This guardrail asserts that never happens.
 *
 * The check has two halves, because probe `text` evidence has two shapes:
 *
 * 1. **Vocabulary.** Every value is a member of a closed set defined in our own
 *    source (`ResolveFailure`, `DohOutcome`, `AddressClass`, `AttemptPhase`,
 *    the TLS protocol allowlist) or one of our own literals. The sets below are
 *    typed as `Record<Union, true>`, so adding a member to the union in `src/`
 *    without adding it here fails the typecheck rather than silently widening
 *    what this test accepts.
 * 2. **Machine codes.** `code` evidence is the one value that is not a closed
 *    set - an OS errno space cannot be enumerated, and reporting the code
 *    verbatim is the point (`egress.unclassified` exists to say "we could not
 *    name this, here is the code"). It is bounded by *shape* instead, and the
 *    only producer of those codes, `extractCode`, is asserted to enforce that
 *    shape, so a resolver's error message can never become one.
 *
 * Every finding the M1 probes can produce is walked: both probes, every
 * recorded fixture, plus the resolver outcomes that have no fixture file.
 */

const ATTEMPT_DIR = join(import.meta.dirname, '..', 'fixtures', 'attempts');
const DOH_DIR = join(import.meta.dirname, '..', 'fixtures', 'doh');

/** Failure classes the DNS probe may name. Exhaustive by construction. */
const RESOLVE_FAILURES: Record<ResolveFailure, true> = {
  'name-not-found': true,
  'no-address-records': true,
  'resolver-timeout': true,
  'resolver-refused': true,
  unclassified: true,
};

/** DoH reachability verdicts. */
const DOH_OUTCOMES: Record<DohOutcome, true> = {
  reachable: true,
  'blocked-dns-failed': true,
  'blocked-dns-timeout': true,
  'blocked-connect-refused': true,
  'blocked-connect-timeout': true,
  'blocked-tls-failed': true,
  'indeterminate-deadline': true,
};

/** Address classes, reported as the `address class` evidence on a split-horizon answer. */
const ADDRESS_CLASSES: Record<AddressClass, true> = {
  public: true,
  private: true,
  sinkhole: true,
  malformed: true,
};

/** Attempt phases, reported as the `phase` evidence on a reset. Ours, not the peer's. */
const ATTEMPT_PHASES: Record<AttemptPhase, true> = { dns: true, connect: true, tls: true, http: true };

/**
 * How the engine classified a probe that threw. The class is the *only* thing
 * it may say about the error - the message is never read - so this union is the
 * whole of that finding's `text` vocabulary.
 */
const PROBE_ERROR_CLASSES: Record<ProbeErrorClass, true> = {
  'network-policy': true,
  aborted: true,
  unclassified: true,
};

/**
 * The TLS protocol names `src/probes/egress/index.ts` will let through. Kept as
 * a literal list rather than an import because the allowlist there is private
 * to that module - and the assertion that matters is the negative one below: a
 * protocol name outside it is dropped, not passed through.
 */
const TLS_PROTOCOLS = ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;

/** Our own stand-in for "the OS gave us no code". Never a remote string. */
const OUR_LITERALS = ['unavailable'] as const;

/** `PacVerdict.kind` (M2), reported as `pac verdict` evidence on an inconclusive PAC result. */
const PAC_VERDICT_KINDS: Record<PacVerdict['kind'], true> = { proxy: true, direct: true, unresolved: true, error: true };

/** `AuthScheme` (M2), reported as `auth scheme` evidence - never the raw `Proxy-Authenticate` value. */
const AUTH_SCHEMES: Record<AuthScheme, true> = { Basic: true, NTLM: true, Negotiate: true, none: true, unknown: true };

/** `NoProxyEntryIssue` (M2), reported as `issue` evidence on a malformed NO_PROXY entry. */
const NO_PROXY_ISSUES: Record<NoProxyEntryIssue, true> = {
  ok: true,
  empty: true,
  'contains-scheme': true,
  'contains-port-with-wildcard': true,
  'invalid-hostname': true,
  'wildcard-not-leading': true,
};

/** `RootReason` (M3), reported as `reason` evidence on the tls root verdict. */
const ROOT_REASONS: Record<RootReason, true> = {
  'bundled-root-on-path': true,
  'self-signed-anchor-not-bundled': true,
  'issuer-matches-no-bundled-root': true,
  'anchor-not-presented': true,
};

/**
 * `TlsCapturePhase` (M3), reported as `phase` evidence on a capture that timed
 * out. Not `AttemptPhase`: the capture seam has a `tunnel` phase and no `http`
 * one, so the two vocabularies overlap without either containing the other.
 */
const TLS_CAPTURE_PHASES: Record<TlsCapturePhase, true> = { dns: true, connect: true, tunnel: true, tls: true };

/** Which path a chain was captured over (M3). Our own knowledge, not the peer's. */
const CAPTURE_PATHS: Record<CapturedChain['via'], true> = { direct: true, proxy: true };

/** `TrustStoreKind` (M4), reported as the `store` evidence on every OS-store finding. */
const TRUST_STORE_KINDS: Record<TrustStoreKind, true> = {
  'macos-system-roots': true,
  'macos-admin-anchors': true,
  'windows-machine-root': true,
  'linux-ca-bundle': true,
};

/** `TrustStoreFailure` (M4), reported as the `failure` evidence. Includes the one the probe synthesises. */
const TRUST_STORE_FAILURES: Record<TrustStoreFailure, true> = {
  'unsupported-platform': true,
  'reader-missing': true,
  'reader-failed': true,
  aborted: true,
  timeout: true,
  'output-too-large': true,
  'no-certificates': true,
};

/** `RuntimeStoreKind` (M4), reported as the `store` evidence on a runtime-store finding. */
const RUNTIME_STORE_KINDS: Record<RuntimeStoreKind, true> = {
  'node-bundled': true,
  'node-extra-ca': true,
  'go-ssl-cert-file': true,
  'go-ssl-cert-dir': true,
  'go-system-bundle': true,
  'python-certifi': true,
  'python-ssl-cert-file': true,
  'python-requests-ca-bundle': true,
  'java-cacerts': true,
  'platform-verifier': true,
};

/** `RuntimeStoreFailure` (M4). `no-certificates` is shared with the OS union above; a Set dedupes it. */
const RUNTIME_STORE_FAILURES: Record<RuntimeStoreFailure, true> = {
  'not-configured': true,
  'not-found': true,
  unreadable: true,
  'output-too-large': true,
  'unsupported-format': true,
  'unsupported-encoding': true,
  truncated: true,
  encrypted: true,
  'no-certificates': true,
};

/** Which keystore container was found, reported as `format` evidence on the java findings. */
const KEYSTORE_FORMATS: Record<NonNullable<RuntimeStoreOutcome['format']>, true> = { jks: true, pkcs12: true };

/**
 * How an observed anchor was tied to a missing one (M4). A literal list rather
 * than an import, because the union is private to the cross-check - and the
 * assertion that matters is that these two words never merge into one.
 */
const MATCH_STRENGTHS = ['bytes', 'issuer-name'] as const;

const TEXT_VOCABULARY: ReadonlySet<string> = new Set([
  ...Object.keys(RESOLVE_FAILURES),
  ...Object.keys(DOH_OUTCOMES),
  ...Object.keys(ADDRESS_CLASSES),
  ...Object.keys(ATTEMPT_PHASES),
  ...Object.keys(PROBE_ERROR_CLASSES),
  ...Object.keys(PAC_VERDICT_KINDS),
  ...Object.keys(AUTH_SCHEMES),
  ...Object.keys(NO_PROXY_ISSUES),
  ...Object.keys(ROOT_REASONS),
  ...Object.keys(TLS_CAPTURE_PHASES),
  ...Object.keys(CAPTURE_PATHS),
  ...Object.keys(TRUST_STORE_KINDS),
  ...Object.keys(TRUST_STORE_FAILURES),
  ...Object.keys(RUNTIME_STORE_KINDS),
  ...Object.keys(RUNTIME_STORE_FAILURES),
  ...Object.keys(KEYSTORE_FORMATS),
  ...MATCH_STRENGTHS,
  ...TLS_PROTOCOLS,
  // The profile's `tls.min_version`, echoed back as the floor a protocol failed
  // to clear. It comes from the profile schema, never from the network.
  ...TLS_VERSIONS,
  ...OUR_LITERALS,
]);

/**
 * The shape `src/net/dns.ts` narrows every code to before it leaves the seam:
 * uppercase, underscores, digits, short. Prose, a hostname, a certificate
 * subject or a header value cannot survive it. Restated here on purpose - this
 * test is the thing that would notice if that narrowing were relaxed.
 */
const MACHINE_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

/**
 * The trust-store reader's own codes (M4). `code` evidence there is not an
 * errno space: it is `exit:N` and `signal:NAME` for a child that answered
 * badly, plus two words this repo wrote - `run-signal` for a cancelled run and
 * `budget-exhausted` for a store that was never started (ADR-0037). None of it
 * comes from the child, whose stderr is drained and dropped, so the shape is
 * pinned here beside `MACHINE_CODE` rather than widening that regex - an errno
 * and an exit status are different things and a reader should be able to tell
 * from this file which one it is looking at.
 */
const STORE_CODE = /^(?:exit:\d{1,5}|signal:[A-Z][A-Z0-9]{1,14}|run-signal|budget-exhausted)$/;

/** Labels whose value is a machine code rather than a word from our vocabulary. */
const CODE_LABELS: ReadonlySet<string> = new Set(['code']);

function isAllowedText(evidence: Evidence): boolean {
  if (TEXT_VOCABULARY.has(evidence.value)) return true;
  if (!CODE_LABELS.has(evidence.label)) return false;
  return MACHINE_CODE.test(evidence.value) || STORE_CODE.test(evidence.value);
}

function offenders(findings: readonly Finding[]): string[] {
  return findings
    .flatMap((finding) => finding.evidence.map((evidence) => ({ finding, evidence })))
    .filter(({ evidence }) => evidence.kind === 'text' && !isAllowedText(evidence))
    .map(({ finding, evidence }) => `${finding.id}: ${evidence.label}=${JSON.stringify(evidence.value)}`);
}

function textValues(findings: readonly Finding[]): string[] {
  return findings.flatMap((finding) =>
    finding.evidence.filter((evidence) => evidence.kind === 'text').map((evidence) => evidence.value),
  );
}

// --- probe drivers ---------------------------------------------------------
// The same default-parameter seam `test/probe-*.test.ts` uses: recorded
// outcomes in, findings out, no socket.

function endpoint(overrides: Partial<Endpoint> = {}): Endpoint {
  return { host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false, ...overrides };
}

function loaded(endpoints: Endpoint[], dohResolvers: string[] = []): LoadedProfile {
  const profile: Profile = {
    name: 'Fixture profile',
    endpoints,
    doh_resolvers: dohResolvers,
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
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

function proberStub(attempt: EndpointAttempt): EndpointProber {
  return { attempt: (): Promise<EndpointAttempt> => Promise.resolve(attempt) };
}

function resolverStub(outcome: DnsOutcome): DnsResolver {
  return { resolve: (): Promise<DnsOutcome> => Promise.resolve(outcome) };
}

const noProber: EndpointProber = {
  attempt: (): Promise<EndpointAttempt> => {
    throw new Error('the prober must not be used when no DoH resolver is declared');
  },
};

async function fixtures(dir: string): Promise<EndpointAttempt[]> {
  const names = (await readdir(dir)).filter((name) => name.endsWith('.json'));
  expect(names.length).toBeGreaterThan(0);
  return Promise.all(
    names.map(async (name) => JSON.parse(await readFile(join(dir, name), 'utf8')) as EndpointAttempt),
  );
}

/** Both endpoint shapes: 443 (TLS + HTTP) and a bare port, which report differently. */
async function egressFindings(attempt: EndpointAttempt): Promise<Finding[]> {
  const required = await runEgress(context(loaded([endpoint()])), proberStub(attempt));
  const optional = await runEgress(
    context(loaded([endpoint({ port: 5432, required: false })])),
    proberStub(attempt),
  );
  return [...required, ...optional];
}

/**
 * Resolver outcomes have no fixture directory - they are three fields - so the
 * table is written out here, one row per `ResolveFailure` plus every answer
 * shape that produces a finding of its own.
 */
const RESOLVER_OUTCOMES: readonly DnsOutcome[] = [
  { ok: true, addresses: ['93.184.216.34'], elapsedMs: 20 },
  { ok: true, addresses: ['93.184.216.34'], elapsedMs: 5000 },
  { ok: true, addresses: ['10.1.2.3'], elapsedMs: 20 },
  { ok: true, addresses: ['127.0.0.1'], elapsedMs: 20 },
  { ok: true, addresses: [], elapsedMs: 20 },
  { ok: false, code: 'ENOTFOUND', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'ENODATA', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'ETIMEDOUT', abortedBy: null, elapsedMs: 5000 },
  { ok: false, code: 'SERVFAIL', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: 'EPROTO', abortedBy: null, elapsedMs: 12 },
  { ok: false, code: null, abortedBy: 'phase-timeout', elapsedMs: 5000 },
  { ok: false, code: null, abortedBy: 'run-signal', elapsedMs: 30 },
  { ok: false, code: null, abortedBy: null, elapsedMs: 12 },
];

/**
 * Throws the engine's catch has to survive. Every one of them buries a
 * hostname, an address or an absolute path in `.message`, which is exactly why
 * `probeErrorFinding` never reads it.
 */
const HOSTILE_ERRORS: readonly unknown[] = [
  new NetworkPolicyError('build-07.corp.local', 8443),
  Object.assign(new Error('getaddrinfo ENOTFOUND internal.corp.example'), { code: 'ENOTFOUND' }),
  Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:443'), { code: 'ECONNREFUSED' }),
  Object.assign(new Error("ENOENT: no such file or directory, open '/home/jdoe/.config/portcall.yaml'"), {
    code: 'ENOENT',
  }),
  'boom: corp-proxy.internal refused',
  Object.assign(new Error('inspection gateway'), { name: 'CN=Corp TLS Inspection CA, O=Example Ltd' }),
];


/**
 * The tls probe's evaluation half (M3) has no fixture directory either: its
 * input is raw DER, so the chains are built in-process. Every shape that
 * produces a finding is covered, including the two hostile ones - a chain whose
 * issuer DN carries a customer's organisation name, and a protocol name the
 * peer made up.
 */
async function tlsFindings(): Promise<Finding[]> {
  const roots = certificateIndex(PUBLIC_ROOT_CA_PEMS);
  const now = new Date('2026-08-26T00:00:00Z');
  const publicRootPem = PUBLIC_ROOT_CA_PEMS[0] ?? '';

  const publicChain = [
    ...(await syntheticChain([
      { subject: 'CN=api.example.com', issuer: subjectOfPem(publicRootPem), dnsNames: ['api.example.com'] },
    ])),
    derOfPem(publicRootPem),
  ];
  const privateChain = await syntheticChain([
    { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp TLS Inspection CA, O=Acme Corp Ltd', dnsNames: ['wrong.example.net'] },
    { subject: 'CN=Acme Corp TLS Inspection CA, O=Acme Corp Ltd' },
  ]);
  const truncatedChain = await syntheticChain([
    { subject: 'CN=api.example.com', issuer: 'CN=Acme Issuing CA', dnsNames: ['api.example.com'] },
    { subject: 'CN=Acme Issuing CA', issuer: subjectOfPem(publicRootPem) },
  ]);
  const expiredChain = await syntheticChain([
    {
      subject: 'CN=api.example.com',
      issuer: 'CN=Acme Corp TLS Inspection CA, O=Acme Corp Ltd',
      dnsNames: ['api.example.com'],
      notAfter: new Date('2025-01-01T00:00:00Z'),
    },
  ]);

  const capture = (chainDer: readonly Uint8Array[], overrides: Partial<CapturedChain> = {}): CapturedChain => ({
    chainDer,
    negotiatedProtocol: 'TLSv1.3',
    negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
    requestedSni: 'api.example.com',
    via: 'direct',
    ...overrides,
  });

  const chains = [publicChain, privateChain, truncatedChain, expiredChain, [], [new Uint8Array([0x30, 0x01, 0x00])]];
  const protocols = ['TLSv1.3', 'TLSv1', 'TLSv9.9 (openssl 3.0.2 / corp-inspection-gw)', null];

  const evaluated = chains.flatMap((chain) =>
    protocols.flatMap((negotiatedProtocol) =>
      [true, false].flatMap((interception_tolerated) =>
        evaluateChain(
          capture(chain, { negotiatedProtocol }),
          { host: 'api.example.com', required: true },
          { tls: { min_version: '1.2', interception_tolerated } },
          { roots, now },
        ).findings,
      ),
    ),
  );

  return [
    ...evaluated,
    ...compareChains(capture(publicChain), capture(privateChain, { via: 'proxy' }), { host: 'api.example.com' }),
    ...compareChains(capture(publicChain), capture(publicChain, { via: 'proxy' }), { host: 'api.example.com' }),
  ];
}

/**
 * The tls probe's *shell* (M3, WP4) is walked separately from the evaluation
 * above, because it has `text` evidence of its own: the path a capture took,
 * the `code` a capture that never completed died with, and the `phase` a
 * capture that timed out gave up in. Every outcome the capture seam can return
 * is driven through it - the four phases, two of them timed out so `phase` is
 * walked with `tunnel` among its values, a cancelled run, and a successful
 * capture over both paths carrying a chain whose issuer names a customer.
 */
async function tlsShellFindings(): Promise<Finding[]> {
  const chainDer = await syntheticChain([
    { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp TLS Inspection CA, O=Acme Corp Ltd', dnsNames: ['api.example.com'] },
    { subject: 'CN=Acme Corp TLS Inspection CA, O=Acme Corp Ltd' },
  ]);

  const outcomes: readonly TlsChainOutcome[] = [
    {
      ok: true,
      chainDer,
      // A protocol name the peer made up, and a cipher we never report.
      negotiatedProtocol: 'TLSv9.9 (openssl 3.0.2 / corp-inspection-gw)',
      negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
      requestedSni: 'api.example.com',
      timing: { connectMs: 4, tlsMs: 9 },
    },
    { ok: false, phase: 'dns', code: 'ENOTFOUND', abortedBy: null },
    { ok: false, phase: 'connect', code: null, abortedBy: 'phase-timeout' },
    { ok: false, phase: 'tunnel', code: 'HTTP_407', abortedBy: null },
    { ok: false, phase: 'tunnel', code: null, abortedBy: 'phase-timeout' },
    { ok: false, phase: 'tls', code: 'ECONNRESET', abortedBy: null },
    { ok: false, phase: 'tls', code: null, abortedBy: 'run-signal' },
  ];

  const capturerStub = (outcome: TlsChainOutcome): TlsCapture => ({
    capture: (): Promise<TlsChainOutcome> => Promise.resolve(outcome),
  });

  const findings = await Promise.all(
    outcomes.map((outcome) =>
      // A proxy in the environment, so both the direct and the proxied path
      // report - `connection` evidence has two values and only two.
      runTls(
        context(loaded([endpoint()])),
        capturerStub(outcome),
        { HTTPS_PROXY: 'http://proxy.corp.internal:8080' },
        new Date('2026-08-26T00:00:00Z'),
      ),
    ),
  );
  return findings.flat();
}


/**
 * The `truststore` cross-check (M4) has the widest `text` vocabulary in the
 * repo - two store-kind unions, two failure unions, a container format, a match
 * strength and the reader's own codes - and the most dangerous evidence: an OS
 * store holds a customer's private CA, whose DN routinely spells their
 * organisation's name. Every finding the cross-check can emit is driven here,
 * with hostile values in every slot that touches customer data.
 */
async function truststoreFindings(): Promise<Finding[]> {
  const publicRootPem = derToPem(await syntheticCert({ subject: 'CN=Example Public Root CA' }));
  const localRootPem = derToPem(await syntheticCert({ subject: 'CN=Acme Corp Internal Root, O=Acme Corp Ltd' }));
  const localRootDer = derOfPem(localRootPem);

  const osStore = (overrides: Partial<TrustStoreOutcome>): TrustStoreOutcome => ({
    kind: 'linux-ca-bundle',
    locator: '/etc/ssl/certs/ca-certificates.crt',
    pems: [],
    failure: null,
    code: null,
    budgetMs: null,
    ...overrides,
  });

  const runtimeStore = (
    overrides: Partial<RuntimeStoreOutcome> & Pick<RuntimeStoreOutcome, 'runtime' | 'kind' | 'combines'>,
  ): RuntimeStoreOutcome => ({
    locator: null,
    searched: [],
    pems: [],
    format: null,
    partial: false,
    failure: null,
    code: null,
    ...overrides,
  });

  // Every OS-store shape: read, each failure class, both timeout codes, and the
  // empty array that means "this platform has no store to read".
  const osShapes: readonly TrustStoreOutcome[][] = [
    [osStore({ pems: [publicRootPem, localRootPem] })],
    [
      osStore({
        kind: 'macos-system-roots',
        locator: '/System/Library/Keychains/SystemRootCertificates.keychain',
        pems: [localRootPem],
      }),
      osStore({
        kind: 'macos-admin-anchors',
        locator: '/Library/Keychains/System.keychain',
        failure: 'reader-failed',
        code: 'exit:1',
      }),
    ],
    [osStore({ failure: 'reader-missing', code: 'ENOENT' })],
    [osStore({ failure: 'output-too-large', code: 'signal:SIGKILL' })],
    [osStore({ failure: 'no-certificates', code: null })],
    [osStore({ kind: 'windows-machine-root', failure: 'timeout', code: 'signal:SIGKILL', budgetMs: 3_000 })],
    [osStore({ kind: 'windows-machine-root', failure: 'timeout', code: 'budget-exhausted', budgetMs: 0 })],
    [osStore({ failure: 'aborted', code: 'run-signal', budgetMs: 0 })],
    [],
  ];

  // Every runtime-store shape, including a customer's real paths as locators
  // and a `code` from the OS errno space.
  const runtimeStores: readonly RuntimeStoreOutcome[] = [
    runtimeStore({ runtime: 'node', kind: 'node-bundled', combines: 'standalone', pems: [publicRootPem] }),
    runtimeStore({
      runtime: 'node',
      kind: 'node-extra-ca',
      combines: 'adds-to',
      locator: 'C:\\Users\\jdoe\\corp-root.pem',
      searched: ['NODE_EXTRA_CA_CERTS'],
      failure: 'unreadable',
      code: 'EACCES',
    }),
    runtimeStore({
      runtime: 'go',
      kind: 'go-ssl-cert-file',
      combines: 'replaces',
      locator: 'SSL_CERT_FILE',
      searched: ['SSL_CERT_FILE'],
      failure: 'not-configured',
    }),
    runtimeStore({
      runtime: 'go',
      kind: 'go-ssl-cert-dir',
      combines: 'replaces',
      locator: '/home/jdoe/certs',
      searched: ['SSL_CERT_DIR'],
      pems: [publicRootPem],
    }),
    runtimeStore({ runtime: 'go', kind: 'platform-verifier', combines: 'standalone' }),
    runtimeStore({
      runtime: 'python',
      kind: 'python-requests-ca-bundle',
      combines: 'replaces',
      locator: 'REQUESTS_CA_BUNDLE',
      searched: ['REQUESTS_CA_BUNDLE'],
      failure: 'no-certificates',
    }),
    runtimeStore({
      runtime: 'python',
      kind: 'python-certifi',
      combines: 'standalone',
      searched: ['/home/jdoe/.local/lib/python3.13'],
      failure: 'not-found',
    }),
    runtimeStore({
      runtime: 'java',
      kind: 'java-cacerts',
      combines: 'standalone',
      locator: '/home/jdoe/jdk-17/lib/security/cacerts',
      format: 'pkcs12',
      failure: 'encrypted',
    }),
    runtimeStore({
      runtime: 'java',
      kind: 'java-cacerts',
      combines: 'standalone',
      locator: '/opt/jdk-8/jre/lib/security/cacerts',
      format: 'jks',
      pems: [publicRootPem, localRootPem],
    }),
    runtimeStore({
      runtime: 'java',
      kind: 'java-cacerts',
      combines: 'standalone',
      locator: '/opt/jdk-21/lib/security/cacerts',
      failure: 'truncated',
    }),
  ];

  // A chain terminating in the private root, one correlation of each strength.
  const observedAnchors: readonly ObservedAnchor[] = [
    {
      der: localRootDer,
      canonicalIssuer: 'cn=acme corp internal root,o=acme corp ltd',
      canonicalSubject: 'cn=acme corp internal root,o=acme corp ltd',
      host: 'api.example.com',
      via: 'proxy',
      anchorClass: 'private',
    },
    {
      der: null,
      canonicalIssuer: 'cn=acme corp internal root,o=acme corp ltd',
      canonicalSubject: 'cn=api.example.com',
      host: 'api.example.com',
      via: 'direct',
      anchorClass: 'indeterminate',
    },
  ];

  return osShapes.flatMap((osStores) =>
    [observedAnchors, []].flatMap((observed) =>
      crossCheck({
        osStores,
        runtimeStores,
        runtimes: ['node', 'go', 'python', 'java'],
        publicRootPems: [publicRootPem],
        observedAnchors: observed,
        osCommands: OS_TRUSTSTORE_COMMANDS,
      }),
    ),
  );
}

describe('probe evidence kinds guardrail', () => {
  it('no engine probe-error finding carries text evidence from outside our own vocabulary', () => {
    const findings = HOSTILE_ERRORS.map((error) => probeErrorFinding('egress', error));

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no egress finding carries text evidence from outside our own vocabulary', async () => {
    const findings = (await Promise.all((await fixtures(ATTEMPT_DIR)).map(egressFindings))).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no dns finding carries text evidence from outside our own vocabulary', async () => {
    const findings = (
      await Promise.all(
        RESOLVER_OUTCOMES.map((outcome) =>
          runDns(context(loaded([endpoint()])), resolverStub(outcome), noProber),
        ),
      )
    ).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no doh finding carries text evidence from outside our own vocabulary', async () => {
    const profile = loaded([endpoint()], ['dns.example.com']);
    const findings = (
      await Promise.all(
        (await fixtures(DOH_DIR)).map((attempt) =>
          runDns(context(profile), resolverStub({ ok: true, addresses: ['93.184.216.34'], elapsedMs: 20 }), proberStub(attempt)),
        ),
      )
    ).flat();
    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no proxy finding carries text evidence from outside our own vocabulary', async () => {
    const profile: LoadedProfile = {
      id: 'fixture',
      source: 'builtin',
      profile: {
        name: 'Fixture profile',
        endpoints: [endpoint({ host: 'a.example.com' }), endpoint({ host: 'b.example.com', port: 80, required: false })],
        doh_resolvers: [],
        runtimes: ['node'],
        tls: { min_version: '1.2', interception_tolerated: true },
        proxy: { pac_url: 'https://pac.corp.internal/proxy.pac' },
      },
    };

    const noTiming = { dnsMs: null, connectMs: null, tlsMs: null, httpMs: null };
    const pacFetcher: PacFetcher = {
      fetch: (): Promise<PacFetchOutcome> =>
        Promise.resolve({
          ok: true,
          script: 'function FindProxyForURL(url, host) { return "PROXY proxy.corp.internal:8080"; }',
          elapsedMs: 4,
        }),
    };
    const connect = (): Promise<ProxyConnectDetail> =>
      Promise.resolve({
        attempt: { ok: false, phase: 'tunnel' as const, code: 'HTTP_407', status: 407, abortedBy: null, timing: noTiming },
        // A realm/token-bearing header, exactly the shape that must never survive into evidence.
        proxyAuthenticate: 'NTLM TlRMTVNTUAABAAAA, Basic realm="do-not-leak-this-realm"',
      });

    const findings = await runProxy(context(profile), resolverStub({ ok: true, addresses: ['93.184.216.34'], elapsedMs: 5 }), pacFetcher, connect);

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
    expect(JSON.stringify(findings)).not.toMatch(/do-not-leak-this-realm|TlRMTVNTUAABAAAA/);
  });

  it('drops a TLS protocol name it does not recognise rather than reporting it', async () => {
    const hostile = 'TLSv9.9 (openssl 3.0.2 / corp-inspection-gw)';
    const attempt: EndpointAttempt = {
      ok: true,
      addresses: ['93.184.216.34'],
      tlsProtocol: hostile,
      status: 200,
      timing: { dnsMs: 4, connectMs: 10, tlsMs: 20, httpMs: 30 },
    };

    const findings = await runEgress(context(loaded([endpoint()])), proberStub(attempt));

    expect(findings.map((finding) => finding.id)).toEqual(['egress.reachable']);
    expect(textValues(findings)).toEqual([]);
    expect(offenders(findings)).toEqual([]);
  });

  it('reports a recognised TLS protocol, so the filter above is a filter and not a blanket drop', async () => {
    const attempt: EndpointAttempt = {
      ok: true,
      addresses: ['93.184.216.34'],
      tlsProtocol: 'TLSv1.3',
      status: 200,
      timing: { dnsMs: 4, connectMs: 10, tlsMs: 20, httpMs: 30 },
    };

    const findings = await runEgress(context(loaded([endpoint()])), proberStub(attempt));

    expect(textValues(findings)).toEqual(['TLSv1.3']);
  });

  it('no tls finding carries text evidence from outside our own vocabulary', async () => {
    const findings = await tlsFindings();

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  it('no tls probe-shell finding carries text evidence from outside our own vocabulary', async () => {
    const findings = await tlsShellFindings();

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  /**
   * The reason `dn` exists as a kind (M3): a private CA's distinguished name is
   * the customer's own organisation name. `text` would cross the redaction
   * boundary in the clear, and `hostname` would be mislabelled `<host:...>` in
   * the report. So every DN-shaped value has to be `dn` - or `public`, which is
   * reserved for a root that matched the runtime's own bundle and is therefore
   * already public knowledge.
   */
  it('never carries a distinguished name under a kind that would leak or mislabel it', async () => {
    const named = (await tlsFindings())
      .flatMap((finding) => finding.evidence.map((evidence) => ({ finding, evidence })))
      .filter(({ evidence }) => /(^|,\s*)(CN|O|OU)=/.test(evidence.value));

    expect(named.length).toBeGreaterThan(0);
    expect(
      named
        .filter(({ evidence }) => evidence.kind !== 'dn' && evidence.kind !== 'public')
        .map(({ finding, evidence }) => `${finding.id}: ${evidence.label} is ${evidence.kind}`),
    ).toEqual([]);
  });


  it('no truststore finding carries text evidence from outside our own vocabulary', async () => {
    const findings = await truststoreFindings();

    expect(findings.length).toBeGreaterThan(0);
    expect(offenders(findings)).toEqual([]);
  });

  /**
   * The reason `dn` and `path` exist as kinds, restated for M4: an OS anchor's
   * subject is the customer's own organisation name, and a runtime store's
   * locator is a path inside their home directory. Both have to arrive under a
   * kind redaction hashes - never `text`, which crosses the boundary in the
   * clear.
   */
  it('never carries an anchor DN or a store path under a kind that would leak it', async () => {
    const named = (await truststoreFindings())
      .flatMap((finding) => finding.evidence.map((evidence) => ({ finding, evidence })))
      .filter(
        ({ evidence }) => /(^|,\s*)(CN|O|OU)=/.test(evidence.value) || /^(?:\/|[A-Z]:\\)/.test(evidence.value),
      );

    expect(named.length).toBeGreaterThan(0);
    expect(
      named
        .filter(({ evidence }) => evidence.kind !== 'dn' && evidence.kind !== 'path' && evidence.kind !== 'public')
        .map(({ finding, evidence }) => `${finding.id}: ${evidence.label} is ${evidence.kind}`),
    ).toEqual([]);
  });

  it("accepts the trust-store reader's own codes and still rejects prose in one", () => {
    for (const code of ['exit:1', 'signal:SIGKILL', 'run-signal', 'budget-exhausted', 'ENOENT']) {
      expect(isAllowedText({ label: 'code', value: code, kind: 'text' })).toBe(true);
    }
    for (const hostile of ['exit: the store is busy', 'signal: killed by corp-av', 'Get-ChildItem failed']) {
      expect(isAllowedText({ label: 'code', value: hostile, kind: 'text' })).toBe(false);
    }
  });

  it('would reject a remote string that reached code evidence', () => {
    // The vocabulary rule has one hole by design - `code` - so the shape rule
    // that plugs it is asserted directly, on the strings this exists to stop.
    for (const hostile of [
      'Server: nginx/1.25.3 (Ubuntu)',
      'unable to verify the first certificate for corp-proxy.internal',
      'CN=Corp TLS Inspection CA, O=Example Ltd',
      'ECONNREFUSED connecting to 10.1.2.3:443',
    ]) {
      expect(isAllowedText({ label: 'code', value: hostile, kind: 'text' })).toBe(false);
    }
  });

  it('the seam that produces code evidence emits nothing but a machine code', () => {
    // `extractCode` is the only source of the `code` field on an attempt or a
    // resolver outcome, so the shape rule above holds only as long as it does.
    expect(extractCode(Object.assign(new Error('handshake failed'), { code: 'ECONNRESET' }))).toBe('ECONNRESET');
    expect(extractCode({ code: 'Server: nginx/1.25.3 (Ubuntu)' })).toBeNull();
    expect(extractCode({ code: 'CN=Corp TLS Inspection CA' })).toBeNull();
    expect(extractCode(new Error('unable to verify the first certificate'))).toBeNull();
    expect(extractCode({ code: 'E'.repeat(65) })).toBeNull();
  });

  it('accepts every machine code the M1 fixtures carry', async () => {
    const codes = (await fixtures(ATTEMPT_DIR))
      .map((attempt) => (attempt.ok ? null : attempt.code))
      .filter((code): code is string => code !== null);

    expect(codes.length).toBeGreaterThan(0);
    for (const code of codes) expect(MACHINE_CODE.test(code)).toBe(true);
  });
});
