import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  JAVA_CACERTS_PATHS,
  MAX_DISCOVERY_MATCHES,
  MAX_RUNTIME_STORE_BYTES,
  PYTHON_CERTIFI_PATHS,
  goSystemBundleStore,
  runtimeStoreReader,
} from '../src/net/runtime-stores.ts';
import { LINUX_CA_BUNDLE_PATHS } from '../src/net/os-truststore.ts';
import { RUNTIMES, type Runtime } from '../src/profiles/schema.ts';
import type { RuntimeStoreKind, RuntimeStoreOutcome } from '../src/net/types.ts';

/**
 * Runtime store discovery (M4, WP3). Two halves, deliberately separated:
 *
 * 1. **The postcondition** - at least one outcome per requested runtime, on
 *    every platform, including one this reader has no table for. It is the
 *    mirror image of the OS reader's rule (where an empty array *is* the
 *    answer), and the cross-check depends on it, so it is asserted first and
 *    over every runtime rather than as an afterthought on one.
 * 2. **The discovery itself**, driven by the committed tree under
 *    `test/fixtures/truststore/runtime/` - a virtualenv, a JDK 9+ and a JDK 8
 *    layout, an `SSL_CERT_DIR`. That tree is a *layout*, not a recording; see
 *    its `make-tree.ts`. Boundary cases a committed file cannot express (a
 *    directory where a bundle should be, a scan with more matches than the cap)
 *    use a temp dir.
 *
 * Every case passes `platform` and `env` explicitly - the reader reads
 * neither off `process` - so the linux, darwin and win32 branches are all
 * exercised on whichever runner the suite is on.
 *
 * The environment is not the only thing a case has to control, though. The
 * table rows that glob under `/usr/lib/jvm` and `/usr/lib/python3` name
 * absolute host paths, and a CI runner has real JDKs and a real system Python
 * sitting on exactly those paths. Discovery finds them - correctly - so a case
 * about the fixture tree that counted outcomes counted the runner's software.
 * Every case about a *found* store therefore either asks for a platform the
 * reader has no table for (`NO_TABLE`, below), which confines discovery to
 * what the environment names, or asserts on the store inside the fixture tree
 * (`oneFromFixtures`). Nothing here may depend on what is installed on the
 * machine running it, in either direction.
 *
 * Only the host-independent part of a table can be reached from a test - no
 * test can conjure `/usr/lib/jvm` - which is why the tables' own shape is
 * asserted directly at the end.
 */

const FIXTURES = join(import.meta.dirname, 'fixtures', 'truststore', 'runtime');

function fixture(...parts: string[]): string {
  return join(FIXTURES, ...parts);
}

async function read(
  runtimes: readonly Runtime[],
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  maxBytes = MAX_RUNTIME_STORE_BYTES,
): Promise<readonly RuntimeStoreOutcome[]> {
  return runtimeStoreReader.read(runtimes, { env, platform, maxBytes });
}

/**
 * Compared with separators normalised. Every case names a `platform`
 * explicitly, so a case that asks for the linux tables while running on
 * Windows gets `/` back for a fixture path the host spells with `\` - which
 * is the reader behaving correctly (a locator is spelled the way the platform
 * under test spells it), not a mismatch worth pinning per-runner.
 */
function samePath(actual: string | null, expected: string): void {
  expect(actual?.split('\\').join('/')).toBe(expected.split('\\').join('/'));
}

function ofKind(outcomes: readonly RuntimeStoreOutcome[], kind: RuntimeStoreKind): RuntimeStoreOutcome[] {
  return outcomes.filter((outcome) => outcome.kind === kind);
}

function one(outcomes: readonly RuntimeStoreOutcome[], kind: RuntimeStoreKind): RuntimeStoreOutcome {
  const matches = ofKind(outcomes, kind);
  expect(matches, `expected exactly one ${kind} outcome`).toHaveLength(1);
  return matches[0] as RuntimeStoreOutcome;
}

/**
 * A platform the reader has no discovery table for, so the only paths it can
 * reach are the ones `JAVA_HOME` and `VIRTUAL_ENV` name. A case that asks for
 * it is searching the fixture tree and nothing else, on every runner. That half
 * of discovery is platform-independent apart from how a locator is spelled, and
 * `samePath` normalises that away.
 */
const NO_TABLE: NodeJS.Platform = 'freebsd';

/**
 * The one outcome of `kind` naming a store inside the fixture tree, for a case
 * that needs a real platform table and so cannot ask for exactly one outcome: a
 * runner with a system certifi contributes rows of its own, and that is the
 * reader working rather than a failure.
 */
function oneFromFixtures(outcomes: readonly RuntimeStoreOutcome[], kind: RuntimeStoreKind): RuntimeStoreOutcome {
  const root = FIXTURES.split('\\').join('/');
  const matches = ofKind(outcomes, kind).filter((outcome) =>
    (outcome.locator?.split('\\').join('/') ?? '').startsWith(root),
  );
  expect(matches, `expected exactly one ${kind} outcome under the fixture tree`).toHaveLength(1);
  return matches[0] as RuntimeStoreOutcome;
}

const PLATFORMS: readonly NodeJS.Platform[] = ['linux', 'darwin', 'win32', 'freebsd', 'aix'];

describe('runtime store reader postcondition', () => {
  it('answers for a runtime on a platform it has no table for, rather than omitting it', async () => {
    const outcomes = await read(['java'], 'freebsd', {});
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]?.kind).toBe('java-cacerts');
    expect(outcomes[0]?.runtime).toBe('java');
    // Never `unsupported-platform`: no such runtime failure exists, and only
    // the OS reader's empty array is allowed to mean "this platform".
    expect(outcomes[0]?.failure).toBe('not-found');
  });

  it.each(PLATFORMS)('gives every requested runtime at least one outcome on %s', async (platform) => {
    const outcomes = await read(RUNTIMES, platform, {});
    for (const runtime of RUNTIMES) {
      expect(
        outcomes.filter((outcome) => outcome.runtime === runtime).length,
        `${runtime} has no outcome on ${platform}`,
      ).toBeGreaterThanOrEqual(1);
    }
    // And nothing is invented for a runtime nobody asked about.
    expect(new Set(outcomes.map((outcome) => outcome.runtime))).toEqual(new Set(RUNTIMES));
  });

  it('asks about one runtime and answers about that runtime only', async () => {
    const outcomes = await read(['go'], 'linux', {});
    expect(outcomes.every((outcome) => outcome.runtime === 'go')).toBe(true);
  });

  it('never throws on a machine where nothing is configured and nothing is installed', async () => {
    await expect(read(RUNTIMES, 'linux', { HOME: fixture('does-not-exist') })).resolves.toBeDefined();
  });

  it('caps `searched`, so no finding can print an unbounded list of a customer path', async () => {
    for (const platform of PLATFORMS) {
      for (const outcome of await read(RUNTIMES, platform, {})) {
        expect(outcome.searched.length).toBeLessThanOrEqual(MAX_DISCOVERY_MATCHES);
      }
    }
  });
});

describe('node', () => {
  it('reports the bundled roots as a store with nothing to search for', async () => {
    const bundled = one(await read(['node'], 'linux', {}), 'node-bundled');
    expect(bundled.locator).toBeNull();
    expect(bundled.searched).toEqual([]);
    expect(bundled.combines).toBe('standalone');
    expect(bundled.failure).toBeNull();
    expect(bundled.pems.length).toBeGreaterThan(0);
  });

  it('adds NODE_EXTRA_CA_CERTS to the bundle rather than replacing it', async () => {
    const extra = one(await read(['node'], 'linux', { NODE_EXTRA_CA_CERTS: fixture('extra-ca.pem') }), 'node-extra-ca');
    expect(extra.combines).toBe('adds-to');
    samePath(extra.locator, fixture('extra-ca.pem'));
    // The variable *and* the path it named: "we read what it pointed at" is a
    // different sentence from "we noticed the variable".
    expect(extra.searched).toEqual(['NODE_EXTRA_CA_CERTS', fixture('extra-ca.pem')]);
    expect(extra.failure).toBeNull();
    expect(extra.pems).toHaveLength(2);
  });

  it('says the variable is unset, which is neither an error nor a missing file', async () => {
    const extra = one(await read(['node'], 'linux', {}), 'node-extra-ca');
    expect(extra.failure).toBe('not-configured');
    expect(extra.locator).toBe('NODE_EXTRA_CA_CERTS');
    expect(extra.pems).toEqual([]);
    expect(extra.code).toBeNull();
  });

  it('separates a variable pointing at nothing from one pointing at something unreadable', async () => {
    const missing = one(await read(['node'], 'linux', { NODE_EXTRA_CA_CERTS: fixture('nope.pem') }), 'node-extra-ca');
    expect(missing.failure).toBe('not-found');
    expect(missing.code).toBe('ENOENT');

    const directory = one(await read(['node'], 'linux', { NODE_EXTRA_CA_CERTS: FIXTURES }), 'node-extra-ca');
    expect(directory.failure).toBe('unreadable');
    expect(directory.code).not.toBeNull();
  });

  it('refuses a bundle larger than the cap instead of buffering it', async () => {
    const outcomes = await read(['node'], 'linux', { NODE_EXTRA_CA_CERTS: fixture('extra-ca.pem') }, 16);
    const extra = one(outcomes, 'node-extra-ca');
    expect(extra.failure).toBe('output-too-large');
    expect(extra.pems).toEqual([]);
  });

  it('reports a file with no certificate in it as read-but-empty', async () => {
    const notes = fixture('ssl-cert-dir', 'notes.txt');
    const empty = one(await read(['node'], 'linux', { NODE_EXTRA_CA_CERTS: notes }), 'node-extra-ca');
    expect(empty.failure).toBe('no-certificates');
  });
});

describe('go', () => {
  it('reads SSL_CERT_FILE as a replacement for the default set', async () => {
    const file = one(await read(['go'], 'linux', { SSL_CERT_FILE: fixture('extra-ca.pem') }), 'go-ssl-cert-file');
    expect(file.combines).toBe('replaces');
    expect(file.pems).toHaveLength(2);
  });

  it('reads every certificate in SSL_CERT_DIR and nothing else in it', async () => {
    const dir = one(await read(['go'], 'linux', { SSL_CERT_DIR: fixture('ssl-cert-dir') }), 'go-ssl-cert-dir');
    expect(dir.combines).toBe('replaces');
    samePath(dir.locator, fixture('ssl-cert-dir'));
    // `.pem` and `.crt`, in name order. `notes.txt` is not a certificate.
    expect(dir.searched).toHaveLength(2);
    samePath(dir.searched[0] ?? null, fixture('ssl-cert-dir', 'one-root.pem'));
    samePath(dir.searched[1] ?? null, fixture('ssl-cert-dir', 'two-root.crt'));
    expect(dir.pems).toHaveLength(2);
    expect(dir.failure).toBeNull();
  });

  it('says so when SSL_CERT_DIR names a directory that is not there', async () => {
    const dir = one(await read(['go'], 'linux', { SSL_CERT_DIR: fixture('nope') }), 'go-ssl-cert-dir');
    expect(dir.failure).toBe('not-found');
    expect(dir.code).toBe('ENOENT');
  });

  it.each<NodeJS.Platform>(['darwin', 'win32'])('reports the platform verifier on %s, where Go asks the OS', async (platform) => {
    const verifier = one(await read(['go'], platform, {}), 'platform-verifier');
    expect(verifier.locator).toBeNull();
    expect(verifier.searched).toEqual([]);
    expect(verifier.pems).toEqual([]);
    expect(verifier.failure).toBeNull();
  });

  it('reports no platform verifier on linux, where Go reads a bundle', async () => {
    expect(ofKind(await read(['go'], 'linux', {}), 'platform-verifier')).toEqual([]);
  });

  it('reports no platform verifier once the environment overrides the set', async () => {
    const outcomes = await read(['go'], 'darwin', { SSL_CERT_FILE: fixture('extra-ca.pem') });
    expect(ofKind(outcomes, 'platform-verifier')).toEqual([]);
  });

  it('reads the system bundle on linux as one store, judged like any other', async () => {
    // Only the shape: the row exists whether or not the runner has a bundle at
    // one of the six paths, and asserting contents here would assert the host.
    const bundle = one(await read(['go'], 'linux', {}), 'go-system-bundle');
    expect(bundle.combines).toBe('standalone');
  });

  it('reports no system bundle once the environment overrides the set', async () => {
    const outcomes = await read(['go'], 'linux', { SSL_CERT_FILE: fixture('extra-ca.pem') });
    expect(ofKind(outcomes, 'go-system-bundle')).toEqual([]);
  });
});

describe('go system bundle', () => {
  // The helper takes `paths` for the reason the OS reader's bundle read does:
  // the real rows are absolute host paths, and a case that statted them would
  // pass on a linux runner and fail on a Windows one (see the file comment).
  const NOPE = fixture('does-not-exist', 'ca-bundle.pem');

  it('reads the first path that exists and records the ones tried before it', async () => {
    const outcome = await goSystemBundleStore([NOPE, fixture('extra-ca.pem')], MAX_RUNTIME_STORE_BYTES);
    expect(outcome.runtime).toBe('go');
    expect(outcome.kind).toBe('go-system-bundle');
    expect(outcome.combines).toBe('standalone');
    samePath(outcome.locator, fixture('extra-ca.pem'));
    expect(outcome.searched).toEqual([NOPE, fixture('extra-ca.pem')]);
    expect(outcome.pems).toHaveLength(2);
    expect(outcome.failure).toBeNull();
  });

  it('reports not-found, listing every path it tried, when no row exists', async () => {
    // Six rows, shaped like the real table, none of them present.
    const missing = LINUX_CA_BUNDLE_PATHS.map((path) => fixture('does-not-exist') + path);
    const outcome = await goSystemBundleStore(missing, MAX_RUNTIME_STORE_BYTES);
    expect(outcome.failure).toBe('not-found');
    // No locator: there is no file to name (the certifi rule, for the same reason).
    expect(outcome.locator).toBeNull();
    expect(outcome.searched).toEqual(missing);
    expect(outcome.searched).toHaveLength(6);
    expect(outcome.pems).toEqual([]);
  });

  it('reports a bundle with no certificate in it as read-but-empty', async () => {
    const outcome = await goSystemBundleStore([fixture('ssl-cert-dir', 'notes.txt')], MAX_RUNTIME_STORE_BYTES);
    expect(outcome.failure).toBe('no-certificates');
  });

  it('refuses a bundle larger than the cap instead of buffering it', async () => {
    const outcome = await goSystemBundleStore([fixture('extra-ca.pem')], 16);
    expect(outcome.failure).toBe('output-too-large');
    expect(outcome.pems).toEqual([]);
  });

  it('separates a path that is unreadable from one that is not there', async () => {
    // A directory where a bundle should be: it exists, so it is not skipped,
    // and reading it fails with an errno worth reporting.
    const outcome = await goSystemBundleStore([FIXTURES], MAX_RUNTIME_STORE_BYTES);
    expect(outcome.failure).toBe('unreadable');
    expect(outcome.code).not.toBeNull();
  });

  it('is handed the OS reader\'s own table, so the two sets cannot drift', async () => {
    // The soundness of the cross-check rests on Go and the OS reference reading
    // one constant. The argument is not observable through `read` (the helper
    // seam exists precisely so no case stats the real rows), so the call is
    // pinned in the source, the way the subprocess guardrail pins its table.
    const source = await readFile(join(import.meta.dirname, '..', 'src', 'net', 'runtime-stores.ts'), 'utf8');
    expect(source).toContain('goSystemBundleStore(LINUX_CA_BUNDLE_PATHS, lookup.maxBytes)');
  });
});

describe('python', () => {
  it('reads REQUESTS_CA_BUNDLE and SSL_CERT_FILE as replacements', async () => {
    const outcomes = await read(['python'], 'linux', {
      REQUESTS_CA_BUNDLE: fixture('extra-ca.pem'),
      SSL_CERT_FILE: fixture('extra-ca.pem'),
    });
    for (const kind of ['python-requests-ca-bundle', 'python-ssl-cert-file'] as const) {
      const outcome = one(outcomes, kind);
      expect(outcome.combines).toBe('replaces');
      expect(outcome.pems).toHaveLength(2);
    }
  });

  it('finds certifi inside a posix virtualenv', async () => {
    const certifi = one(await read(['python'], NO_TABLE, { VIRTUAL_ENV: fixture('virtualenv') }), 'python-certifi');
    samePath(certifi.locator, fixture('virtualenv', 'lib', 'python3.12', 'site-packages', 'certifi', 'cacert.pem'));
    expect(certifi.combines).toBe('standalone');
    expect(certifi.pems).toHaveLength(1);
  });

  it('finds certifi inside a virtualenv that puts site-packages under Lib, as a Windows one does', async () => {
    // Both spellings are tried on every platform, because a venv can be copied
    // between machines (see `certifiStores`), so the `Lib` layout is reachable
    // without asking for `win32` - which would spell this fixture's own posix
    // path the Windows way and find nothing on a posix runner.
    const certifi = one(await read(['python'], NO_TABLE, { VIRTUAL_ENV: fixture('virtualenv-win') }), 'python-certifi');
    samePath(certifi.locator, fixture('virtualenv-win', 'Lib', 'site-packages', 'certifi', 'cacert.pem'));
    expect(certifi.pems).toHaveLength(1);
  });

  it('finds a per-user certifi by glob under HOME, with no variable set at all', async () => {
    // The one case that needs a platform table - the `~` row is in it - and so
    // the one that also reads past the fixture tree on a runner with a system
    // certifi installed.
    const certifi = oneFromFixtures(await read(['python'], 'linux', { HOME: fixture('home') }), 'python-certifi');
    samePath(certifi.locator, fixture('home', '.local', 'lib', 'python3.13', 'site-packages', 'certifi', 'cacert.pem'));
  });

  it('reports one not-found outcome, listing where it looked, when there is no certifi', async () => {
    // A virtualenv that is not there: two patterns tried, nothing behind
    // either, and the row saying so is the point. Named through the fixture
    // tree so the answer cannot depend on the runner having a certifi.
    const certifi = one(await read(['python'], NO_TABLE, { VIRTUAL_ENV: fixture('does-not-exist') }), 'python-certifi');
    expect(certifi.failure).toBe('not-found');
    expect(certifi.locator).toBeNull();
    expect(certifi.searched.length).toBeGreaterThan(0);
    expect(certifi.searched.join('\n')).toContain('site-packages');
  });
});

describe('java', () => {
  it('finds the JDK 9+ cacerts under JAVA_HOME and judges it on its own', async () => {
    const cacerts = one(await read(['java'], NO_TABLE, { JAVA_HOME: fixture('java-home-9') }), 'java-cacerts');
    samePath(cacerts.locator, fixture('java-home-9', 'lib', 'security', 'cacerts'));
    expect(cacerts.combines).toBe('standalone');
    // The fixture's `cacerts` is an ASCII placeholder (make-tree.ts), not a real
    // keystore, so `readKeystore` correctly rejects it on the magic bytes alone -
    // the container reader itself is exercised in test/net-java-keystore.test.ts.
    expect(cacerts.failure).toBe('unsupported-format');
    expect(cacerts.pems).toEqual([]);
    expect(cacerts.format).toBeNull();
    expect(cacerts.partial).toBe(false);
  });

  it('finds the JDK 8 cacerts, which lives one level deeper', async () => {
    const cacerts = one(await read(['java'], NO_TABLE, { JAVA_HOME: fixture('java-home-8') }), 'java-cacerts');
    samePath(cacerts.locator, fixture('java-home-8', 'jre', 'lib', 'security', 'cacerts'));
  });

  it('names the places it looked when there is no JDK', async () => {
    // `JAVA_HOME` pointed at a directory that is not there, rather than an empty
    // environment: this case pins "a runtime with nothing installed still gets
    // a row", and on a runner with a JDK in `/usr/lib/jvm` an empty environment
    // reaches a real store and never exercises that branch at all.
    const cacerts = one(await read(['java'], NO_TABLE, { JAVA_HOME: fixture('does-not-exist') }), 'java-cacerts');
    expect(cacerts.failure).toBe('not-found');
    expect(cacerts.locator).toBeNull();
    expect(cacerts.searched.join('\n')).toContain('cacerts');
  });

  it('refuses a cacerts larger than the cap', async () => {
    const cacerts = one(await read(['java'], NO_TABLE, { JAVA_HOME: fixture('java-home-9') }, 4), 'java-cacerts');
    expect(cacerts.failure).toBe('output-too-large');
  });
});

describe('discovery bounds', () => {
  it('reads at most MAX_DISCOVERY_MATCHES certificates out of a large SSL_CERT_DIR', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'portcall-cert-dir-'));
    try {
      for (let index = 0; index < MAX_DISCOVERY_MATCHES + 4; index += 1) {
        await writeFile(join(dir, `root-${String(index).padStart(2, '0')}.pem`), 'not a certificate\n');
      }
      const outcome = one(await read(['go'], 'linux', { SSL_CERT_DIR: dir }), 'go-ssl-cert-dir');
      expect(outcome.searched).toHaveLength(MAX_DISCOVERY_MATCHES);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('stops a wildcard scan that matches more pythons than the cap', async () => {
    const home = await mkdtemp(join(tmpdir(), 'portcall-home-'));
    try {
      for (let index = 0; index < MAX_DISCOVERY_MATCHES + 4; index += 1) {
        const leaf = join(home, '.local', 'lib', `python3.${String(index)}`, 'site-packages', 'certifi');
        await mkdir(leaf, { recursive: true });
        await writeFile(join(leaf, 'cacert.pem'), 'not a certificate\n');
      }
      const outcomes = ofKind(await read(['python'], 'linux', { HOME: home }), 'python-certifi');
      expect(outcomes.length).toBeLessThanOrEqual(MAX_DISCOVERY_MATCHES);
      expect(outcomes.length).toBeGreaterThan(1);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  });
});

describe('the discovery tables', () => {
  it('names a store for each platform the project targets', () => {
    for (const platform of ['linux', 'darwin', 'win32'] as const) {
      expect(JAVA_CACERTS_PATHS[platform]?.length, `no java paths for ${platform}`).toBeGreaterThan(0);
      expect(PYTHON_CERTIFI_PATHS[platform]?.length, `no python paths for ${platform}`).toBeGreaterThan(0);
    }
  });

  it('names no personal keystore and no key container anywhere', () => {
    const every = [...Object.values(JAVA_CACERTS_PATHS), ...Object.values(PYTHON_CERTIFI_PATHS)].flat();
    expect(every.length).toBeGreaterThan(0);
    for (const path of every) {
      // SPEC.md 4.2: discovery may name a public trust store and nothing else.
      expect(path).not.toMatch(/\.p12|\.pf[x]|\.jks|\.ssh|id_rsa/i);
      expect(path.endsWith('cacerts') || path.endsWith('cacert.pem'), `unexpected leaf: ${path}`).toBe(true);
    }
  });

  it('holds the bounds the plan names', () => {
    expect(MAX_RUNTIME_STORE_BYTES).toBe(8 * 1024 * 1024);
    expect(MAX_DISCOVERY_MATCHES).toBe(8);
  });
});
