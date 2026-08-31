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

beforeAll(async () => {
  const profile = loadedProfile();
  const context: ProbeContext = {
    profile,
    net: new NetworkGuard(profile.profile),
    deadline: Date.now() + 60_000,
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
  locallyAddedSha256 = new Set();
  for (const store of osOutcomes) {
    if (store.failure !== null) continue;
    for (const pem of store.pems) {
      const der = new Uint8Array(new X509Certificate(pem).rawData);
      const hash = sha256Hex(der);
      if (seen.has(hash)) continue;
      seen.add(hash);
      if (!publicIndex.hasCertificate(der)) locallyAddedSha256.add(hash);
    }
  }
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

  it('produces `truststore.node.missing-root` at degraded severity', () => {
    const missing = findingsById(findings, 'truststore.node.missing-root');
    expect(missing.length).toBeGreaterThan(0);
    for (const finding of missing) expect(finding.severity).toBe('degraded');
  });

  it('names the injected root’s DN in that finding’s evidence, as `dn` evidence', () => {
    const missing = findingsById(findings, 'truststore.node.missing-root');
    const dnEntries = missing.flatMap((finding) => finding.evidence.filter((entry) => entry.kind === 'dn'));
    expect(dnEntries.length).toBeGreaterThan(0);
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
