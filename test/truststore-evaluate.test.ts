import { beforeAll, describe, expect, it } from 'vitest';
import { crossCheck, osEvidenceLevel } from '../src/probes/truststore/evaluate.ts';
import type { CrossCheckInput } from '../src/probes/truststore/evaluate.ts';
import { OS_TRUSTSTORE_COMMANDS } from '../src/net/os-truststore.ts';
import { derToPem } from '../src/net/pem.ts';
import type { RuntimeStoreOutcome, TrustStoreOutcome } from '../src/net/types.ts';
import type { ObservedAnchor } from '../src/engine/index.ts';
import type { Finding } from '../src/model/finding.ts';
import { syntheticCert } from './helpers/synthetic-chain.ts';

/**
 * The pure cross-check (M4, WP6). Every case is asserted as the **whole ordered
 * list of `id=severity` pairs**, the discipline
 * `test/tls-recorded-chains.test.ts` uses and for its reason: the ids are API,
 * so a case that only asserted "contains a missing-root" would let a second,
 * contradictory finding appear beside it unnoticed.
 *
 * The certificates are built in process rather than committed, matching
 * `test/helpers/synthetic-chain.ts`'s own argument: every property under test
 * here is a *shape* - this root is in that store and not this one - and a
 * committed PEM would pin one shape per file plus a regeneration ritual. The
 * committed fixtures for this milestone are the ones that pin a *parser*
 * (`test/fixtures/truststore/`), which is what CLAUDE.md's rule is about.
 */

const PUBLIC_ROOT = 'CN=Example Public Root CA, O=Example Trust Services';
const LOCAL_ROOT = 'CN=Acme Corp Internal Root, O=Acme Corp Ltd';
const OTHER_LOCAL_ROOT = 'CN=Acme Corp Inspection CA, O=Acme Corp Ltd';

/**
 * Blocks the readers *do* hand on - well-formed base64 `CERTIFICATE` blocks -
 * whose payload is not a certificate. That is the shape a malformed certificate
 * in a customer's own store arrives in. Two of them, differing, because a store
 * of identical blocks would also pass a test that deduplicated them away.
 */
const UNPARSABLE_PEM = ['-----BEGIN CERTIFICATE-----', 'bm90IGEgY2VydGlmaWNhdGU=', '-----END CERTIFICATE-----'].join(
  '\n',
);
const OTHER_UNPARSABLE_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'c3RpbGwgbm90IGEgY2VydGlmaWNhdGU=',
  '-----END CERTIFICATE-----',
].join('\n');

let publicRootPem: string;
let localRootPem: string;
let localRootDer: Uint8Array;
let otherLocalRootPem: string;

beforeAll(async () => {
  const publicDer = await syntheticCert({ subject: PUBLIC_ROOT });
  publicRootPem = derToPem(publicDer);
  localRootDer = await syntheticCert({ subject: LOCAL_ROOT });
  localRootPem = derToPem(localRootDer);
  otherLocalRootPem = derToPem(await syntheticCert({ subject: OTHER_LOCAL_ROOT }));
});

/** The linux row, which has no subprocess and therefore no budget. */
function osStore(overrides: Partial<TrustStoreOutcome> = {}): TrustStoreOutcome {
  return {
    kind: 'linux-ca-bundle',
    locator: '/etc/ssl/certs/ca-certificates.crt',
    pems: [],
    failure: null,
    code: null,
    budgetMs: null,
    ...overrides,
  };
}

function runtimeStore(
  runtime: RuntimeStoreOutcome['runtime'],
  overrides: Partial<RuntimeStoreOutcome> & Pick<RuntimeStoreOutcome, 'kind' | 'combines'>,
): RuntimeStoreOutcome {
  return {
    runtime,
    locator: null,
    searched: [],
    pems: [],
    format: null,
    partial: false,
    failure: null,
    code: null,
    ...overrides,
  };
}

function nodeBundle(pems: readonly string[]): RuntimeStoreOutcome {
  return runtimeStore('node', { kind: 'node-bundled', combines: 'standalone', pems });
}

function input(overrides: Partial<CrossCheckInput> = {}): CrossCheckInput {
  return {
    platform: 'linux',
    osStores: [osStore({ pems: [publicRootPem, localRootPem] })],
    runtimeStores: [nodeBundle([publicRootPem])],
    runtimes: ['node'],
    publicRootPems: [publicRootPem],
    observedAnchors: [],
    osCommands: OS_TRUSTSTORE_COMMANDS,
    ...overrides,
  };
}

/** The whole verdict, in order. */
function verdict(findings: readonly Finding[]): string[] {
  return findings.map((finding) => `${finding.id}=${finding.severity}`);
}

function evidence(finding: Finding, label: string): string[] {
  return finding.evidence.filter((item) => item.label === label).map((item) => item.value);
}

function byId(findings: readonly Finding[], id: string): Finding {
  const found = findings.find((finding) => finding.id === id);
  // Thrown rather than asserted, so the caller gets a `Finding` and not a
  // `Finding | undefined` to unwrap at every use.
  if (found === undefined) throw new Error(`expected a ${id} finding`);
  return found;
}

function observed(overrides: Partial<ObservedAnchor> = {}): ObservedAnchor {
  return {
    der: localRootDer,
    canonicalIssuer: 'cn=acme corp internal root,o=acme corp ltd',
    canonicalSubject: 'cn=acme corp internal root,o=acme corp ltd',
    host: 'api.example.com',
    via: 'direct',
    anchorClass: 'private',
    ...overrides,
  };
}

describe('truststore cross-check', () => {
  it('reports a root this machine trusts and Node does not', () => {
    const findings = crossCheck(input());

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=degraded']);
    const missing = byId(findings, 'truststore.node.missing-root');
    expect(evidence(missing, 'anchor')).toEqual([LOCAL_ROOT]);
    expect(missing.evidence.find((item) => item.label === 'anchor')?.kind).toBe('dn');
    expect(evidence(byId(findings, 'truststore.os.read'), 'locally added')).toEqual(['1']);
  });

  it('raises the same root to a blocker when the tls probe saw those exact bytes', () => {
    const findings = crossCheck(input({ observedAnchors: [observed()] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=blocker']);
    const missing = byId(findings, 'truststore.node.missing-root');
    expect(evidence(missing, 'host')).toEqual(['api.example.com']);
    expect(evidence(missing, 'match')).toEqual(['bytes']);
    expect(evidence(missing, 'connection')).toEqual(['direct']);
  });

  /**
   * D4's regression test. `CrossCheckInput` carries no interception-tolerance
   * flag at all, and that is the point: a profile saying "an inspecting proxy
   * is expected here" is not saying "a root this runtime cannot verify against
   * is fine", so there is no input through which the verdict could be softened.
   */
  it('has no input that could soften a correlated blocker', () => {
    const keys = Object.keys(input());

    expect(keys).not.toContain('profile');
    expect(JSON.stringify(keys)).not.toMatch(/interception/i);
  });

  it('correlates by issuer name, and says so, when the peer sent no root', () => {
    const findings = crossCheck(input({ observedAnchors: [observed({ der: null, via: 'proxy' })] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=blocker']);
    const missing = byId(findings, 'truststore.node.missing-root');
    expect(evidence(missing, 'match')).toEqual(['issuer-name']);
    expect(missing.remediation).toContain('the match is by name and not by bytes');
  });

  /**
   * Contract item 17. `indeterminate` says the `tls` probe could not tell a
   * private anchor from a public one - routinely a public root re-issued under
   * the same subject DN - and a name-only match against a maybe is not evidence
   * that this chain is the one failing. The finding stays `degraded` and drops
   * the correlation rather than rounding it up to `blocker`.
   */
  it('does not escalate a name-only match when the observed anchor class is indeterminate', () => {
    const findings = crossCheck(input({ observedAnchors: [observed({ der: null, anchorClass: 'indeterminate' })] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=degraded']);
    const missing = byId(findings, 'truststore.node.missing-root');
    expect(evidence(missing, 'match')).toEqual([]);
    expect(evidence(missing, 'host')).toEqual([]);
  });

  it('still escalates a name-only match when the observed anchor class is private', () => {
    const findings = crossCheck(input({ observedAnchors: [observed({ der: null, anchorClass: 'private' })] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=blocker']);
    expect(evidence(byId(findings, 'truststore.node.missing-root'), 'match')).toEqual(['issuer-name']);
  });

  /** Byte identity is proof on its own: the class it was graded as adds nothing. */
  it('escalates a byte match whatever class the anchor was graded', () => {
    const findings = crossCheck(input({ observedAnchors: [observed({ anchorClass: 'indeterminate' })] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.missing-root=blocker']);
    expect(evidence(byId(findings, 'truststore.node.missing-root'), 'match')).toEqual(['bytes']);
  });

  it('reports roots-present when the runtime holds every locally added anchor', () => {
    const findings = crossCheck(input({ runtimeStores: [nodeBundle([publicRootPem, localRootPem])] }));

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.roots-present=ok']);
  });

  it('reports an unreadable NODE_EXTRA_CA_CERTS, which Node ignores in silence', () => {
    const findings = crossCheck(
      input({
        runtimeStores: [
          nodeBundle([publicRootPem]),
          runtimeStore('node', {
            kind: 'node-extra-ca',
            combines: 'adds-to',
            locator: '/etc/pki/corp-root.pem',
            searched: ['NODE_EXTRA_CA_CERTS', '/etc/pki/corp-root.pem'],
            failure: 'unreadable',
            code: 'EACCES',
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.read=ok',
      'truststore.node.extra-ca-unreadable=degraded',
      'truststore.node.missing-root=degraded',
    ]);
    expect(byId(findings, 'truststore.node.extra-ca-unreadable').remediation).toContain('without warning');
  });

  it('counts NODE_EXTRA_CA_CERTS into the bundle it adds to', () => {
    const findings = crossCheck(
      input({
        runtimeStores: [
          nodeBundle([publicRootPem]),
          runtimeStore('node', {
            kind: 'node-extra-ca',
            combines: 'adds-to',
            locator: '/etc/pki/corp-root.pem',
            pems: [localRootPem],
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.read=ok',
      'truststore.node.extra-ca-configured=ok',
      'truststore.node.roots-present=ok',
    ]);
  });

  it('judges two JDKs separately, so a root in one and not the other is still a finding', () => {
    const findings = crossCheck(
      input({
        runtimes: ['java'],
        runtimeStores: [
          runtimeStore('java', {
            kind: 'java-cacerts',
            combines: 'standalone',
            locator: '/opt/jdk-17/lib/security/cacerts',
            pems: [publicRootPem, localRootPem],
          }),
          runtimeStore('java', {
            kind: 'java-cacerts',
            combines: 'standalone',
            locator: '/opt/jdk-8/jre/lib/security/cacerts',
            pems: [publicRootPem],
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.read=ok',
      'truststore.java.roots-present=ok',
      'truststore.java.missing-root=degraded',
    ]);
    expect(evidence(byId(findings, 'truststore.java.missing-root'), 'runtime store')).toEqual([
      '/opt/jdk-8/jre/lib/security/cacerts',
    ]);
  });

  it('says go asks the platform on win32 rather than inventing a missing root for it', () => {
    const findings = crossCheck(
      input({
        platform: 'win32',
        runtimes: ['go'],
        runtimeStores: [
          runtimeStore('go', {
            kind: 'go-ssl-cert-file',
            combines: 'replaces',
            locator: 'SSL_CERT_FILE',
            searched: ['SSL_CERT_FILE'],
            failure: 'not-configured',
          }),
          runtimeStore('go', {
            kind: 'go-ssl-cert-dir',
            combines: 'replaces',
            locator: 'SSL_CERT_DIR',
            searched: ['SSL_CERT_DIR'],
            failure: 'not-configured',
          }),
          runtimeStore('go', { kind: 'platform-verifier', combines: 'standalone' }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.go.platform-verifier=ok']);
  });

  it('judges the bundle go reads on linux like any other store, with no special case', () => {
    // `go-system-bundle` arrives as one more standalone store: the cross-check
    // needs no branch for it, which is the point of the reader emitting it.
    const goBundle = (pems: readonly string[]): RuntimeStoreOutcome =>
      runtimeStore('go', {
        kind: 'go-system-bundle',
        combines: 'standalone',
        locator: '/etc/ssl/certs/ca-certificates.crt',
        searched: ['/etc/ssl/certs/ca-certificates.crt'],
        pems,
      });

    const present = crossCheck(
      input({ runtimes: ['go'], runtimeStores: [goBundle([publicRootPem, localRootPem])] }),
    );
    expect(verdict(present)).toEqual(['truststore.os.read=ok', 'truststore.go.roots-present=ok']);

    const missing = crossCheck(input({ runtimes: ['go'], runtimeStores: [goBundle([publicRootPem])] }));
    expect(verdict(missing)).toEqual(['truststore.os.read=ok', 'truststore.go.missing-root=degraded']);
    expect(evidence(byId(missing, 'truststore.go.missing-root'), 'anchor')).toEqual([LOCAL_ROOT]);
  });

  it('manufactures neither verdict for a keystore it could not open', () => {
    const findings = crossCheck(
      input({
        runtimes: ['java'],
        runtimeStores: [
          runtimeStore('java', {
            kind: 'java-cacerts',
            combines: 'standalone',
            locator: '/opt/jdk-17/lib/security/cacerts',
            format: 'pkcs12',
            failure: 'encrypted',
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.java.store-unreadable=unknown']);
    expect(byId(findings, 'truststore.java.store-unreadable').remediation).toContain('never supplies a keystore');
  });

  it('lists where it looked when a declared runtime has no store at all', () => {
    const findings = crossCheck(
      input({
        runtimes: ['python'],
        runtimeStores: [
          runtimeStore('python', {
            kind: 'python-certifi',
            combines: 'standalone',
            searched: ['/usr/lib/python3*/site-packages/certifi/cacert.pem', '/home/jo/.local/lib/python3*'],
            failure: 'not-found',
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.python.store-not-found=unknown']);
    expect(evidence(byId(findings, 'truststore.python.store-not-found'), 'searched')).toHaveLength(2);
  });

  it('counts a root held by both macOS keychains once', () => {
    const findings = crossCheck(
      input({
        platform: 'darwin',
        osStores: [
          osStore({
            kind: 'macos-system-roots',
            locator: '/System/Library/Keychains/SystemRootCertificates.keychain',
            pems: [publicRootPem, localRootPem],
          }),
          osStore({
            kind: 'macos-admin-anchors',
            locator: '/Library/Keychains/System.keychain',
            pems: [localRootPem],
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.read=ok',
      'truststore.os.read=ok',
      'truststore.node.missing-root=degraded',
    ]);
    expect(evidence(byId(findings, 'truststore.node.missing-root'), 'missing anchors')).toEqual(['1']);
  });

  it('is deterministic, DN ordering included', () => {
    const shape = input({
      osStores: [osStore({ pems: [publicRootPem, otherLocalRootPem, localRootPem] })],
    });

    expect(crossCheck(shape)).toEqual(crossCheck(shape));
    expect(evidence(byId(crossCheck(shape), 'truststore.node.missing-root'), 'anchor')).toEqual([
      OTHER_LOCAL_ROOT,
      LOCAL_ROOT,
    ]);
  });

  /**
   * `locally added` sits on a *per-store* finding, so it counts that store: the
   * run-wide deduplicated total printed under a store holding one anchor reads
   * as a subset larger than the set it sits inside.
   */
  it('counts locally added per store rather than run-wide', () => {
    const findings = crossCheck(
      input({
        platform: 'darwin',
        osStores: [
          osStore({
            kind: 'macos-system-roots',
            locator: '/System/Library/Keychains/SystemRootCertificates.keychain',
            pems: [publicRootPem, localRootPem, otherLocalRootPem],
          }),
          osStore({
            kind: 'macos-admin-anchors',
            locator: '/Library/Keychains/System.keychain',
            pems: [localRootPem],
          }),
        ],
      }),
    );

    const reads = findings.filter((finding) => finding.id === 'truststore.os.read');
    expect(reads.map((read) => evidence(read, 'anchors'))).toEqual([['3'], ['1']]);
    expect(reads.map((read) => evidence(read, 'locally added'))).toEqual([['2'], ['1']]);
  });

  it('counts the blocks in a store it could not parse instead of dropping them in silence', () => {
    const findings = crossCheck(
      input({ osStores: [osStore({ pems: [publicRootPem, localRootPem, UNPARSABLE_PEM] })] }),
    );

    const read = byId(findings, 'truststore.os.read');
    expect(evidence(read, 'anchors')).toEqual(['2']);
    expect(evidence(read, 'unparsable certificates')).toEqual(['1']);
  });

  it('says nothing was parsed rather than reporting a clean store of zero anchors', () => {
    const findings = crossCheck(input({ osStores: [osStore({ pems: [UNPARSABLE_PEM, OTHER_UNPARSABLE_PEM] })] }));

    const read = byId(findings, 'truststore.os.read');
    expect(evidence(read, 'anchors')).toEqual(['0']);
    expect(evidence(read, 'unparsable certificates')).toEqual(['2']);
  });

  it('leaves the count off a store every block of which parsed', () => {
    expect(evidence(byId(crossCheck(input()), 'truststore.os.read'), 'unparsable certificates')).toEqual([]);
  });

  /**
   * `partial` is `failure: null` with half the bags unread, so nothing else in
   * the pipeline flags it: an `ok` verdict here would be green over anchors
   * portcall never saw.
   */
  it('emits no clean verdict over a keystore only part of which could be read', () => {
    const findings = crossCheck(
      input({
        runtimes: ['java'],
        runtimeStores: [
          runtimeStore('java', {
            kind: 'java-cacerts',
            combines: 'standalone',
            locator: '/opt/jdk-17/lib/security/cacerts',
            format: 'pkcs12',
            pems: [publicRootPem, localRootPem],
            partial: true,
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.java.store-unreadable=unknown']);
    expect(findings.map((finding) => finding.id)).not.toContain('truststore.java.roots-present');
    const unreadable = byId(findings, 'truststore.java.store-unreadable');
    expect(evidence(unreadable, 'failure')).toEqual(['encrypted-entries']);
    expect(unreadable.remediation).toContain('never supplies a keystore password');
  });

  it('marks a missing-root built from a partly read keystore as built on a partial read', () => {
    const findings = crossCheck(
      input({
        runtimes: ['java'],
        runtimeStores: [
          runtimeStore('java', {
            kind: 'java-cacerts',
            combines: 'standalone',
            locator: '/opt/jdk-17/lib/security/cacerts',
            format: 'pkcs12',
            pems: [publicRootPem],
            partial: true,
          }),
        ],
      }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.read=ok',
      'truststore.java.store-unreadable=unknown',
      'truststore.java.missing-root=degraded',
    ]);
    expect(evidence(byId(findings, 'truststore.java.missing-root'), 'runtime store read')).toEqual(['partial']);
  });
});

describe('truststore cross-check, when the OS store could not be read', () => {
  it('grades the evidence by how much of the store was seen', () => {
    expect(osEvidenceLevel([osStore()])).toBe('complete');
    expect(osEvidenceLevel([osStore(), osStore({ failure: 'reader-missing', code: 'ENOENT' })])).toBe('partial');
    expect(osEvidenceLevel([osStore({ failure: 'reader-missing', code: 'ENOENT' })])).toBe('none');
    expect(osEvidenceLevel([])).toBe('none');
  });

  it('emits neither verdict, and says why, when every store failed', () => {
    const findings = crossCheck(
      input({ osStores: [osStore({ pems: [], failure: 'reader-missing', code: 'ENOENT' })] }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.unreadable=unknown',
      'truststore.crosscheck.indeterminate=unknown',
    ]);
    expect(findings.map((finding) => finding.id)).not.toContain('truststore.node.roots-present');
  });

  it('says the platform has no reader rather than that its store is broken', () => {
    const findings = crossCheck(input({ platform: 'freebsd', osStores: [] }));

    expect(verdict(findings)).toEqual([
      'truststore.os.unreadable=unknown',
      'truststore.crosscheck.indeterminate=unknown',
    ]);
    expect(evidence(byId(findings, 'truststore.os.unreadable'), 'failure')).toEqual(['unsupported-platform']);
  });

  it('blames the cancellation, not the machine, when the run was aborted', () => {
    const findings = crossCheck(
      input({ osStores: [osStore({ failure: 'aborted', code: 'run-signal', budgetMs: 0 })] }),
    );

    expect(verdict(findings)).toEqual([
      'truststore.os.aborted=unknown',
      'truststore.crosscheck.indeterminate=unknown',
    ]);
    expect(byId(findings, 'truststore.os.aborted').remediation).toContain('nothing here is a verdict about');
  });

  it('carries the store counts on a verdict built from a partial read', () => {
    const findings = crossCheck(
      input({
        platform: 'darwin',
        osStores: [
          osStore({ kind: 'macos-system-roots', pems: [publicRootPem, localRootPem] }),
          osStore({ kind: 'macos-admin-anchors', failure: 'reader-failed', code: 'exit:1' }),
        ],
        runtimeStores: [nodeBundle([publicRootPem, localRootPem])],
      }),
    );

    expect(verdict(findings)).toEqual(['truststore.os.read=ok', 'truststore.node.roots-present=ok']);
    const present = byId(findings, 'truststore.node.roots-present');
    expect(evidence(present, 'stores read')).toEqual(['1']);
    expect(evidence(present, 'stores unread')).toEqual(['1']);
  });
});

describe('truststore read-timeout remediation', () => {
  const WIN32_CEILING = OS_TRUSTSTORE_COMMANDS.find((command) => command.kind === 'windows-machine-root')?.timeoutMs;

  function timedOut(budgetMs: number, code: string): Finding {
    const findings = crossCheck(
      input({
        platform: 'win32',
        osStores: [
          osStore({
            kind: 'windows-machine-root',
            locator: 'the machine root store',
            failure: 'timeout',
            code,
            budgetMs,
          }),
        ],
      }),
    );
    return byId(findings, 'truststore.os.read-timeout');
  }

  it('tells an operator to raise --timeout when the run budget is what bound the read', () => {
    expect(WIN32_CEILING).toBeDefined();
    const finding = timedOut((WIN32_CEILING ?? 0) - 2_000, 'signal:SIGKILL');

    expect(finding.severity).toBe('unknown');
    expect(finding.remediation).toContain('re-run with --timeout raised to give it more room');
    expect(evidence(finding, 'budget applied (ms)')).toEqual([String((WIN32_CEILING ?? 0) - 2_000)]);
  });

  /**
   * The polarity that matters: at the row's own ceiling, `--timeout` is not the
   * knob. Portcall exposes none for the row, so telling the reader to raise the
   * run budget would send them to wait longer for the identical answer.
   */
  it('refuses to promise --timeout when the store outran its own ceiling', () => {
    const finding = timedOut(WIN32_CEILING ?? 0, 'signal:SIGKILL');

    expect(finding.remediation).toContain('would only wait longer for the same answer');
    expect(finding.remediation).not.toContain('--timeout raised');
  });

  it('names the run, not the machine, when the budget was exhausted before the spawn', () => {
    const finding = timedOut(0, 'budget-exhausted');

    expect(finding.remediation).toContain("The run's remaining time ran out before this store was read");
    expect(finding.remediation).toContain('--timeout raised');
    // Zero is not a duration anything was given, so it is never rendered as
    // one: the row's unused ceiling is what the evidence shows instead.
    expect(evidence(finding, 'budget applied (ms)')).toEqual([]);
    expect(evidence(finding, 'store budget, never applied (ms)')).toEqual([String(WIN32_CEILING)]);
    expect(evidence(finding, 'code')).toEqual(['budget-exhausted']);
  });

  it('names the store through its locator and never through a tool the guardrail owns', () => {
    const finding = timedOut(3_000, 'signal:SIGKILL');

    expect(finding.remediation).toContain('the machine root store');
    expect(finding.remediation).not.toMatch(/certutil|security find-/i);
  });
});
