import { createHash } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { beforeAll, describe, expect, it } from 'vitest';
import { runTruststore } from '../../src/probes/truststore/index.ts';
import { certificateIndex } from '../../src/probes/shared/root-index.ts';
import { NetworkGuard } from '../../src/net/guard.ts';
import { osTrustStoreReader } from '../../src/net/os-truststore.ts';
import { MAX_RUNTIME_STORE_BYTES, runtimeStoreReader } from '../../src/net/runtime-stores.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../../src/net/root-bundle.ts';
import type { ProbeContext } from '../../src/engine/index.ts';
import type { Finding } from '../../src/model/finding.ts';
import type { LoadedProfile } from '../../src/profiles/schema.ts';

/**
 * The three-OS proof (M4, WP7, SPEC.md §7): does the truststore probe
 * actually notice a root injected into the *real* trust store of the machine
 * it is running on, on each of the three operating systems portcall ships for.
 *
 * `test/truststore-evaluate.test.ts` already proves the cross-check logic
 * against fixtures; nothing here duplicates that. What only a real runner can
 * prove is the *edge* - `os-truststore.ts` actually shelling out to `security`
 * or PowerShell or opening `/etc/ssl/certs/ca-certificates.crt`, on the real
 * three platforms, against a store this suite's own CI step has just mutated.
 *
 * The injection itself is not this repo's to do: CLAUDE.md forbids config
 * mutation outside the working directory, and a developer's own machine trust
 * store is exactly that. `.github/workflows/ci.yml`'s `truststore-proof` job
 * does the injection, inside a disposable CI runner, before this file runs.
 */

/**
 * Reads `PORTCALL_TEST_ROOT_SHA256`, which `generate-root.mjs` prints and the
 * `truststore-proof` job exports into every step's environment after
 * injecting the root it names. Throws - never skips - when it is unset, so
 * this suite cannot silently report green on a machine nothing was injected
 * into (CLAUDE.md's no-permanently-skipped-test rule). The message names the
 * exact injection command for `process.platform`, so the failure is
 * actionable rather than cryptic when someone runs `test:truststore` by hand.
 */
function requireInjectedRoot(): string {
  const sha256 = process.env.PORTCALL_TEST_ROOT_SHA256;
  if (sha256 !== undefined && sha256.trim() !== '') return sha256.trim();

  const howTo: Readonly<Record<string, string>> = {
    darwin:
      'run `node test/truststore-injected/generate-root.mjs <dir>` and then ' +
      '`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <dir>/root.cer`',
    win32:
      'run `node test/truststore-injected/generate-root.mjs <dir>` and then, in an elevated ' +
      'PowerShell, `Import-Certificate -FilePath <dir>\\root.cer -CertStoreLocation Cert:\\LocalMachine\\Root`',
    linux:
      'run `node test/truststore-injected/generate-root.mjs <dir>` and then ' +
      '`sudo cp <dir>/root.pem /usr/local/share/ca-certificates/portcall-m4.crt && sudo update-ca-certificates`',
  };
  const instruction = howTo[process.platform] ?? `no injection command is known for platform ${process.platform}`;
  throw new Error(
    'PORTCALL_TEST_ROOT_SHA256 is not set, so no throwaway root is known to be injected into this ' +
      `machine's trust store. This suite proves a real injection, on a real OS, and refuses to run ` +
      `without one - it never skips (CLAUDE.md). To run it yourself on ${process.platform}: ${instruction}, ` +
      'capturing the printed PORTCALL_TEST_ROOT_SHA256=<hash> line into the environment before ' +
      '`npm run test:truststore`.',
  );
}

// Module scope, deliberately: the throw must happen before a single test is
// collected, matching the contract's "throws, never skips" - a suite that
// skipped every `it` would still report green.
const expectedRootSha256 = requireInjectedRoot();

/** The `TrustStoreKind`s `truststore.os.read` may legitimately name on this platform. */
const EXPECTED_OS_STORE_KINDS: Readonly<Record<string, readonly string[]>> = {
  darwin: ['macos-system-roots', 'macos-admin-anchors'],
  win32: ['windows-machine-root'],
  linux: ['linux-ca-bundle'],
};

function loadedProfile(): LoadedProfile {
  return {
    id: 'truststore-proof',
    source: 'builtin',
    profile: {
      name: 'Truststore proof fixture',
      endpoints: [{ host: 'api.example.com', port: 443, purpose: 'api', required: true, expect_streaming: false }],
      doh_resolvers: [],
      runtimes: ['node', 'java'],
      tls: { min_version: '1.2', interception_tolerated: true },
    },
  };
}

function sha256Hex(der: Uint8Array): string {
  return createHash('sha256').update(der).digest('hex');
}

function findingsById(findings: readonly Finding[], id: string): Finding[] {
  return findings.filter((finding) => finding.id === id);
}

let findings: Finding[];
/** SHA-256 of every anchor `osTrustStoreReader` read that is not in the runtime's own public bundle. */
let locallyAddedSha256: Set<string>;
/** SHA-256 of every locally-added anchor node's own trust set does not hold - the set `truststore.node.missing-root` reports. */
let missingFromNodeSha256: Set<string>;

beforeAll(async () => {
  const profile = loadedProfile();
  const context: ProbeContext = {
    profile,
    net: new NetworkGuard(profile.profile),
    // One deadline, two serial real reads: `runTruststore` below reads every
    // store on this machine and then the re-derivation does it again, so the
    // second read starts with whatever the first one spent already gone. The
    // windows-machine-root row alone is allowed 60 s, so a 60 s run deadline
    // left the second read a fraction of one row's ceiling.
    deadline: Date.now() + 180_000,
    signal: new AbortController().signal,
    observedAnchors: [],
  };

  // The real edge, both readers: no stub anywhere in this file. This is the
  // one suite in the repo allowed to exercise `osTrustStoreReader` and
  // `runtimeStoreReader` against the machine they actually run on rather than
  // a fixture.
  findings = await runTruststore(context);

  // Independently re-derive "locally added" the same way `crossCheck` does,
  // from the same real OS reader the probe used, so requirement 3 is checked
  // against the actual store contents rather than trusted from the findings'
  // own summary counts.
  const osOutcomes = await osTrustStoreReader.read({ signal: context.signal, deadline: context.deadline });
  const publicIndex = certificateIndex(PUBLIC_ROOT_CA_PEMS);
  const seen = new Set<string>();
  // Keyed by sha256 and carrying the bytes, not only the digest: requirement 3
  // asks its question in sha256, and `certificateIndex` asks its membership
  // question in DER, so requirement 4 needs the certificate itself.
  const locallyAddedDer = new Map<string, Uint8Array>();
  for (const store of osOutcomes) {
    if (store.failure !== null) continue;
    for (const pem of store.pems) {
      const der = new Uint8Array(new X509Certificate(pem).rawData);
      const hash = sha256Hex(der);
      if (seen.has(hash)) continue;
      seen.add(hash);
      if (!publicIndex.hasCertificate(der)) locallyAddedDer.set(hash, der);
    }
  }
  locallyAddedSha256 = new Set(locallyAddedDer.keys());

  // A third read, off the deadline above and cheap where the two store sweeps
  // are not: node's stores are the bundle already in this process plus at most
  // one file `NODE_EXTRA_CA_CERTS` names, so this costs a `stat`, not a
  // subprocess or a machine-wide enumeration.
  //
  // It re-derives the set `runtimeFindings` calls `missing` (evaluate.ts): the
  // locally-added anchors above, less the ones node's own trust set holds.
  // node has exactly one such set - `trustSets` finds no node store that
  // `replaces`, so the bundled roots are the base and `NODE_EXTRA_CA_CERTS`
  // `adds-to` it - which makes the union of node's readable stores that set,
  // with no set-assembly logic to re-implement here.
  const nodeOutcomes = await runtimeStoreReader.read(['node'], {
    env: process.env,
    platform: process.platform,
    maxBytes: MAX_RUNTIME_STORE_BYTES,
  });
  const nodeIndex = certificateIndex(
    nodeOutcomes.filter((outcome) => outcome.failure === null).flatMap((outcome) => outcome.pems),
  );
  missingFromNodeSha256 = new Set(
    [...locallyAddedDer].filter(([, der]) => !nodeIndex.hasCertificate(der)).map(([hash]) => hash),
  );
});

describe('the injected root, read from the real OS trust store', () => {
  it('was actually injected (the gate above did not throw)', () => {
    expect(expectedRootSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces a `truststore.os.read` finding at severity ok, naming this platform’s store', () => {
    const reads = findingsById(findings, 'truststore.os.read');
    expect(reads.length).toBeGreaterThan(0);
    const expectedKinds = EXPECTED_OS_STORE_KINDS[process.platform] ?? [];
    for (const finding of reads) {
      expect(finding.severity).toBe('ok');
      const store = finding.evidence.find((entry) => entry.label === 'store');
      expect(store).toBeDefined();
      expect(expectedKinds).toContain(store?.value);
    }
  });

  it('is among the locally-added anchors the probe observed', () => {
    expect(locallyAddedSha256.has(expectedRootSha256)).toBe(true);
  });

  /**
   * ADR-0042: this requirement's teeth come from the re-derivation above, not
   * from the finding's own evidence, and that is a deliberate narrowing.
   *
   * `missingRootFinding` (evaluate.ts) publishes a count, up to
   * `MAX_REPORTED_DNS` subject DNs, the store's path, a `partial` marker and -
   * only when the `tls` probe fed the run an anchor - correlation entries.
   * There is no fingerprint and no sha256 anywhere on it, so *which* roots the
   * finding is about is not recoverable from it by bytes; adding such an
   * evidence entry would be a change to `src/` behaviour, out of scope for
   * M4's close. `missing.length > 0` alone therefore reads as an injection
   * proof without being one: any machine carrying a locally-added root
   * satisfies it whether or not CI injected anything, and this repo's dev host
   * carried 28 of them when measured 2026-09-01.
   *
   * So the count and the severity stay - they are what the *finding* is
   * asserted to say - and membership is asked of the independently re-derived
   * set instead. On a runner where the injection never happened, the root is
   * in no store either reader can see, `missingFromNodeSha256` cannot hold its
   * hash, and this goes red. That is the property the count alone never had.
   *
   * Severity is `degraded` here by construction rather than by luck:
   * `observedAnchors` is `[]` in this suite's `ProbeContext`, so `correlate()`
   * returns `null` and `evaluate.ts` takes the `degraded` branch every time.
   * The `blocker` promotion is the harness suite's to prove (ADR-0041), on a
   * run that has a live intercepted chain to correlate against.
   */
  it('produces `truststore.node.missing-root` at degraded severity, over a set holding the injected root', () => {
    const missing = findingsById(findings, 'truststore.node.missing-root');
    expect(missing.length).toBeGreaterThan(0);
    for (const finding of missing) expect(finding.severity).toBe('degraded');
    expect(missingFromNodeSha256.has(expectedRootSha256)).toBe(true);
  });

  it('names the injected root’s DN in that finding’s evidence, as `dn` evidence', () => {
    const missing = findingsById(findings, 'truststore.node.missing-root');
    const dnEntries = missing.flatMap((finding) => finding.evidence.filter((entry) => entry.kind === 'dn'));
    expect(dnEntries.length).toBeGreaterThan(0);

    // `MAX_REPORTED_DNS` caps the DN list this finding carries (evaluate.ts),
    // and this suite never runs the `tls` probe - `observedAnchors` is `[]` in
    // the `ProbeContext` above - so `correlate()` always returns `null` here
    // and Bug 4's fix (a correlated anchor jumping the truncation) has nothing
    // to correlate against. On a machine with enough other locally-added
    // anchors (CI's macOS keychains routinely have more than five), the
    // injected root can still be truncated out of this list with no evidence
    // able to save it. `total` is the same count the finding itself already
    // publishes as `missing anchors`; when the DN list is not truncated
    // against it, the injected root must be named. When it is truncated, the
    // OS-read edge this file exists to prove is already covered by "is among
    // the locally-added anchors the probe observed" above - the root's own
    // sha256 in `locallyAddedSha256` - and no assertion is made on DN content.
    const total = missing.reduce((sum, finding) => {
      const count = finding.evidence.find((entry) => entry.label === 'missing anchors');
      return sum + (count === undefined ? 0 : Number(count.value));
    }, 0);
    if (dnEntries.length !== total) return;

    expect(dnEntries.some((entry) => entry.value.includes('Portcall M4 Injected Test Root'))).toBe(true);
  });

  it('is discovered by the java runtime store reader with a non-null format, when JAVA_HOME is set', async () => {
    if (process.env.JAVA_HOME === undefined || process.env.JAVA_HOME.trim() === '') {
      console.log('JAVA_HOME is not set on this runner; the java cacerts assertion has nothing to check.');
      return;
    }
    const outcomes = await runtimeStoreReader.read(['java'], {
      env: process.env,
      platform: process.platform,
      maxBytes: MAX_RUNTIME_STORE_BYTES,
    });
    const cacerts = outcomes.find((outcome) => outcome.kind === 'java-cacerts');
    expect(cacerts).toBeDefined();
    // Printed to the job log on record: whether this runner's shipped cacerts
    // is JKS or PKCS#12, and whether it read cleanly, is exactly the "is it
    // encrypted" question this assertion exists to answer.
    console.log(
      `java-cacerts on ${process.platform}: format=${String(cacerts?.format)} failure=${String(cacerts?.failure)} ` +
        `anchors=${String(cacerts?.pems.length)}`,
    );
    expect(cacerts?.format).not.toBeNull();
  });
});
