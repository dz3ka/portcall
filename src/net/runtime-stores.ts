import { readFile, readdir, stat } from 'node:fs/promises';
import { posix as posixPath, win32 as win32Path } from 'node:path';
import { LINUX_CA_BUNDLE_PATHS } from './os-truststore.ts';
import { pemBlocks } from './pem.ts';
import { PUBLIC_ROOT_CA_PEMS } from './root-bundle.ts';
import type { Runtime } from '../profiles/schema.ts';
import type { RuntimeStoreFailure, RuntimeStoreOutcome, RuntimeStoreReader } from './types.ts';

/**
 * "Where does *each runtime* look for roots, and what is actually there?" -
 * the other half of the M4 seam. `os-truststore.ts` answers what the machine
 * trusts; this answers what Node, Go, Python and Java consult, which on the
 * platforms this tool targets is frequently not the same set. That gap is the
 * whole premise of SPEC.md 1.
 *
 * Four properties hold the design together:
 *
 * 1. **File paths and environment variables only** (ADR-0033). Nothing here
 *    starts a process: no `java -XshowSettings`, no `python -m certifi`, no
 *    `go env`. Running a customer's runtime to ask it about itself would mean
 *    executing a binary off their `PATH` with their `JAVA_TOOL_OPTIONS` in
 *    scope - the exact thing the pinned-argv rule exists to prevent - and it
 *    would be slower and less deterministic than a `stat`.
 * 2. **The layouts are a table, not control flow.** A new JDK or Python layout
 *    is a row in `JAVA_CACERTS_PATHS` / `PYTHON_CERTIFI_PATHS`, reviewable as
 *    data. `platform` and `env` arrive as arguments rather than being read off
 *    `process`, so all three platforms' tables are exercised on one runner.
 * 3. **Bounded.** Every read is capped at `maxBytes`, every wildcard scan at
 *    `MAX_DISCOVERY_MATCHES`, and `searched` is capped by the same number
 *    before it can reach a finding - it is a list of a customer's real paths
 *    (a home directory, a virtualenv), so it is `path` evidence and it is
 *    short.
 * 4. **At least one outcome per requested runtime, always.** A runtime that is
 *    not installed is `not-found` *with* an outcome listing where we looked,
 *    which is the actionable half of that finding. Unlike the OS reader, an
 *    empty answer here would be indistinguishable from "we forgot".
 *
 * A `not-configured` outcome is a *statement about the environment*, not a
 * store: no path was named, nothing was read, and the cross-check must not let
 * one of them shadow a runtime's default set the way a `replaces` store that
 * really was read does.
 *
 * Nothing here reads a private key. No path below names a personal keystore or
 * a key container, only the public `cacerts` and `cacert.pem` files a runtime
 * consults for trust anchors, and Java's bytes go to the keystore reader, which
 * skips key entries by length.
 */

export const MAX_RUNTIME_STORE_BYTES = 8 * 1024 * 1024;

/**
 * A machine with forty JDKs does not get forty reads, and `searched` never
 * grows past a list a person would read in a report.
 */
export const MAX_DISCOVERY_MATCHES = 8;

/**
 * Well-known `cacerts` locations, keyed by platform. `~` is the user's home
 * directory; `*` matches one path segment. `JAVA_HOME` is tried before any of
 * these and is not a row, because it is an environment variable rather than a
 * layout.
 *
 * Each hit is judged separately (a root present in one JDK and missing from
 * another is a real finding, and unioning them would hide it), so a table with
 * several matches is expected, not a problem to be deduplicated away.
 */
export const JAVA_CACERTS_PATHS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  linux: Object.freeze([
    '/usr/lib/jvm/*/lib/security/cacerts',
    '/usr/lib/jvm/*/jre/lib/security/cacerts',
    // Debian's shared store, which the JDKs above are usually symlinked to.
    '/etc/ssl/certs/java/cacerts',
  ]),
  darwin: Object.freeze([
    '/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts',
    '/Library/Java/JavaVirtualMachines/*/Contents/Home/jre/lib/security/cacerts',
    '/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts',
  ]),
  win32: Object.freeze([
    'C:/Program Files/Java/*/lib/security/cacerts',
    'C:/Program Files/Java/*/jre/lib/security/cacerts',
    'C:/Program Files/Eclipse Adoptium/*/lib/security/cacerts',
  ]),
});

/**
 * Well-known `certifi/cacert.pem` locations, keyed by platform. `VIRTUAL_ENV`
 * is tried before any of these, for the same reason `JAVA_HOME` is.
 *
 * Debian's `dist-packages` is a row of its own rather than a wildcard: the two
 * spellings are a packaging decision, not a version, and a `*` broad enough to
 * cover both would also match directories that are neither.
 */
export const PYTHON_CERTIFI_PATHS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  linux: Object.freeze([
    '~/.local/lib/python3*/site-packages/certifi/cacert.pem',
    '/usr/lib/python3*/site-packages/certifi/cacert.pem',
    '/usr/lib/python3/dist-packages/certifi/cacert.pem',
    '/usr/local/lib/python3*/site-packages/certifi/cacert.pem',
    '/usr/local/lib/python3*/dist-packages/certifi/cacert.pem',
  ]),
  darwin: Object.freeze([
    '~/Library/Python/3*/lib/python/site-packages/certifi/cacert.pem',
    '~/.local/lib/python3*/site-packages/certifi/cacert.pem',
    '/opt/homebrew/lib/python3*/site-packages/certifi/cacert.pem',
    '/usr/local/lib/python3*/site-packages/certifi/cacert.pem',
    '/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages/certifi/cacert.pem',
  ]),
  win32: Object.freeze([
    '~/AppData/Local/Programs/Python/Python3*/Lib/site-packages/certifi/cacert.pem',
    '~/AppData/Roaming/Python/Python3*/site-packages/certifi/cacert.pem',
    'C:/Program Files/Python3*/Lib/site-packages/certifi/cacert.pem',
  ]),
});

/** Everything a lookup needs, and nothing read off `process`. */
interface Lookup {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  maxBytes: number;
}

/** An errno off an unknown rejection value, or `null`. Never a message (ADR-0009). */
function errnoCode(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const { code } = error;
    if (typeof code === 'string') return code;
  }
  return null;
}

/**
 * Joined the way the *requested* platform spells paths, not the way the host
 * does: a locator ends up in a report an operator reads, and a Windows path
 * with forward slashes in it reads like a bug even when it resolves.
 */
function joinPath(platform: NodeJS.Platform, ...parts: readonly string[]): string {
  return platform === 'win32' ? win32Path.join(...parts) : posixPath.join(...parts);
}

/** The value of `name` when it is set to something non-empty, else `null`. */
function envValue(env: NodeJS.ProcessEnv, name: string): string | null {
  const value = env[name];
  return value === undefined || value === '' ? null : value;
}

/** The home directory as the platform names it. `USERPROFILE` on Windows. */
function homeDirectory(lookup: Lookup): string | null {
  return lookup.platform === 'win32'
    ? (envValue(lookup.env, 'USERPROFILE') ?? envValue(lookup.env, 'HOME'))
    : envValue(lookup.env, 'HOME');
}

/** A `*` matches within one segment only, so a pattern can never widen a level. */
function segmentMatcher(segment: string, platform: NodeJS.Platform): RegExp {
  const escaped = segment.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^\\\\/]*');
  return new RegExp(`^${escaped}$`, platform === 'win32' ? 'i' : '');
}

/**
 * Every existing path matching `pattern`, at most `MAX_DISCOVERY_MATCHES` of
 * them, in directory-entry name order so two runs on one machine report the
 * same thing. Patterns are written with `/` whatever the platform; `~` is the
 * home directory and expands to nothing when the environment has none, since a
 * pattern rooted at a home directory we cannot name has not been searched.
 */
async function expandPattern(pattern: string, lookup: Lookup): Promise<string[]> {
  const segments = pattern.split('/');
  const first = segments.shift() ?? '';
  let heads: string[];
  if (first === '~') {
    const home = homeDirectory(lookup);
    if (home === null) return [];
    heads = [home];
  } else if (first === '') {
    heads = ['/'];
  } else if (/^[A-Za-z]:$/.test(first)) {
    // A bare `C:` is drive-*relative* to `win32.join`, so the root separator is
    // part of the head there. Posix `join` needs no such help.
    heads = [lookup.platform === 'win32' ? `${first}\\` : first];
  } else {
    heads = [first];
  }

  for (const segment of segments) {
    if (!segment.includes('*')) {
      heads = heads.map((head) => joinPath(lookup.platform, head, segment));
      continue;
    }
    const matcher = segmentMatcher(segment, lookup.platform);
    const expanded: string[] = [];
    for (const head of heads) {
      let entries: string[];
      try {
        entries = await readdir(head);
      } catch {
        // A directory that is not there is the ordinary case: this pattern is
        // one of several tried, and its absence is what `searched` records.
        continue;
      }
      for (const entry of entries.sort()) {
        if (matcher.test(entry)) expanded.push(joinPath(lookup.platform, head, entry));
        if (expanded.length >= MAX_DISCOVERY_MATCHES) break;
      }
      if (expanded.length >= MAX_DISCOVERY_MATCHES) break;
    }
    heads = expanded;
  }

  const found: string[] = [];
  for (const head of heads) {
    if (await exists(head)) found.push(head);
    if (found.length >= MAX_DISCOVERY_MATCHES) break;
  }
  return found;
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/** The first `MAX_DISCOVERY_MATCHES` entries, which is all a finding may print. */
function capped(paths: readonly string[]): readonly string[] {
  return paths.slice(0, MAX_DISCOVERY_MATCHES);
}

interface Contents {
  pems: readonly string[];
  failure: RuntimeStoreFailure | null;
  code: string | null;
}

/**
 * One PEM file, size-checked before it is opened. The three ways this fails are
 * three different tickets: the file is not there, the file is there and we
 * could not open it, the file is there and it is far too big to be a trust
 * store. Collapsing them would leave an operator unable to tell a stale
 * environment variable from a permissions problem.
 */
async function readPemFile(path: string, maxBytes: number): Promise<Contents> {
  let size: number;
  try {
    size = (await stat(path)).size;
  } catch (error) {
    const code = errnoCode(error);
    return { pems: [], failure: code === 'ENOENT' ? 'not-found' : 'unreadable', code };
  }
  if (size > maxBytes) return { pems: [], failure: 'output-too-large', code: null };
  try {
    const pems = pemBlocks(await readFile(path, 'utf8'));
    return { pems, failure: pems.length === 0 ? 'no-certificates' : null, code: null };
  } catch (error) {
    return { pems: [], failure: 'unreadable', code: errnoCode(error) };
  }
}

/** Fields every outcome needs, so a row's interesting parts stay legible. */
function outcome(
  runtime: Runtime,
  fields: Pick<RuntimeStoreOutcome, 'kind' | 'combines'> & Partial<RuntimeStoreOutcome>,
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
    ...fields,
  };
}

/**
 * A store named by an environment variable. Unset is `not-configured` and the
 * locator is the variable's *name*: "portcall checked `SSL_CERT_FILE` and it
 * was not set" is a different sentence from "portcall did not check", and the
 * report has to be able to say which.
 */
async function envFileStore(
  runtime: Runtime,
  kind: RuntimeStoreOutcome['kind'],
  variable: string,
  combines: RuntimeStoreOutcome['combines'],
  lookup: Lookup,
): Promise<RuntimeStoreOutcome> {
  const path = envValue(lookup.env, variable);
  if (path === null) {
    return outcome(runtime, { kind, combines, locator: variable, searched: [variable], failure: 'not-configured' });
  }
  const contents = await readPemFile(path, lookup.maxBytes);
  return outcome(runtime, { kind, combines, locator: path, searched: [variable, path], ...contents });
}

/**
 * `SSL_CERT_DIR` as OpenSSL lays one out: every `.pem` and `.crt` in it, capped,
 * unioned into the one store the directory is. `searched` lists the files
 * actually opened, which is what makes a partial read visible.
 */
async function certDirStore(runtime: Runtime, lookup: Lookup): Promise<RuntimeStoreOutcome> {
  const kind = 'go-ssl-cert-dir';
  const combines = 'replaces';
  const dir = envValue(lookup.env, 'SSL_CERT_DIR');
  if (dir === null) {
    return outcome(runtime, {
      kind,
      combines,
      locator: 'SSL_CERT_DIR',
      searched: ['SSL_CERT_DIR'],
      failure: 'not-configured',
    });
  }

  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (error) {
    const code = errnoCode(error);
    return {
      ...outcome(runtime, { kind, combines, locator: dir, searched: ['SSL_CERT_DIR', dir] }),
      failure: code === 'ENOENT' ? 'not-found' : 'unreadable',
      code,
    };
  }

  const files = entries
    .filter((entry) => /\.(?:pem|crt)$/i.test(entry))
    .sort()
    .slice(0, MAX_DISCOVERY_MATCHES)
    .map((entry) => joinPath(lookup.platform, dir, entry));

  const pems: string[] = [];
  let code: string | null = null;
  for (const file of files) {
    const contents = await readPemFile(file, lookup.maxBytes);
    // One unreadable file in a directory of forty is not a failed store, so the
    // errno is carried and the rest of the directory is still read.
    if (contents.code !== null) code ??= contents.code;
    pems.push(...contents.pems);
  }
  return outcome(runtime, {
    kind,
    combines,
    locator: dir,
    searched: files,
    pems,
    failure: pems.length === 0 ? 'no-certificates' : null,
    code,
  });
}

/** `VIRTUAL_ENV` first, then the platform's table. Every hit is its own store. */
async function certifiStores(lookup: Lookup): Promise<RuntimeStoreOutcome[]> {
  const kind = 'python-certifi';
  const virtualEnv = envValue(lookup.env, 'VIRTUAL_ENV');
  const patterns: string[] = [];
  if (virtualEnv !== null) {
    // A virtualenv puts site-packages under `Lib` on Windows and under
    // `lib/python3.x` everywhere else; both spellings are tried on both, since
    // a venv can be copied between machines and the layout is what it is.
    const root = virtualEnv.replace(/\\/g, '/').replace(/\/+$/, '');
    patterns.push(
      `${root}/lib/python3*/site-packages/certifi/cacert.pem`,
      `${root}/Lib/site-packages/certifi/cacert.pem`,
    );
  }
  patterns.push(...(PYTHON_CERTIFI_PATHS[lookup.platform] ?? []));

  const found: string[] = [];
  for (const pattern of patterns) {
    for (const path of await expandPattern(pattern, lookup)) {
      if (!found.includes(path)) found.push(path);
    }
    if (found.length >= MAX_DISCOVERY_MATCHES) break;
  }

  if (found.length === 0) {
    // No locator: there is no file to name, and naming a path that is not there
    // as `path` evidence would read like a store the machine has. `searched`
    // carries where we looked, which is the actionable half.
    return [outcome('python', { kind, combines: 'standalone', searched: capped(patterns), failure: 'not-found' })];
  }

  const outcomes: RuntimeStoreOutcome[] = [];
  for (const path of capped(found)) {
    const contents = await readPemFile(path, lookup.maxBytes);
    outcomes.push(
      outcome('python', { kind, combines: 'standalone', locator: path, searched: [path], ...contents }),
    );
  }
  return outcomes;
}

/**
 * `JAVA_HOME` first (JDK 9+, then the JDK 8 layout), then the platform's table.
 *
 * The bytes are not parsed here: WP4's keystore reader is what turns a
 * `cacerts` into PEMs, so until it lands a located store reports
 * `unsupported-format`, which is honest - portcall found the file and cannot
 * yet say what is in it - and is the one placeholder a reader of this file
 * should expect to disappear.
 */
async function javaStores(lookup: Lookup): Promise<RuntimeStoreOutcome[]> {
  const kind = 'java-cacerts';
  const javaHome = envValue(lookup.env, 'JAVA_HOME');
  const patterns: string[] = [];
  if (javaHome !== null) {
    const root = javaHome.replace(/\\/g, '/').replace(/\/+$/, '');
    patterns.push(`${root}/lib/security/cacerts`, `${root}/jre/lib/security/cacerts`);
  }
  patterns.push(...(JAVA_CACERTS_PATHS[lookup.platform] ?? []));

  const found: string[] = [];
  for (const pattern of patterns) {
    for (const path of await expandPattern(pattern, lookup)) {
      if (!found.includes(path)) found.push(path);
    }
    if (found.length >= MAX_DISCOVERY_MATCHES) break;
  }

  if (found.length === 0) {
    return [outcome('java', { kind, combines: 'standalone', searched: capped(patterns), failure: 'not-found' })];
  }

  const outcomes: RuntimeStoreOutcome[] = [];
  for (const path of capped(found)) {
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch (error) {
      const code = errnoCode(error);
      outcomes.push(
        outcome('java', { kind, combines: 'standalone', locator: path, searched: [path], failure: 'unreadable', code }),
      );
      continue;
    }
    outcomes.push(
      outcome('java', {
        kind,
        combines: 'standalone',
        locator: path,
        searched: [path],
        failure: size > lookup.maxBytes ? 'output-too-large' : 'unsupported-format',
      }),
    );
  }
  return outcomes;
}

/** Node: the bundle it ships, plus whatever `NODE_EXTRA_CA_CERTS` adds to it. */
async function nodeStores(lookup: Lookup): Promise<RuntimeStoreOutcome[]> {
  const bundled = outcome('node', {
    kind: 'node-bundled',
    combines: 'standalone',
    pems: PUBLIC_ROOT_CA_PEMS,
    failure: PUBLIC_ROOT_CA_PEMS.length === 0 ? 'no-certificates' : null,
  });
  // `adds-to`, not `replaces`: Node appends this file to its bundle, so a root
  // missing from the bundle can be supplied here without the bundle vanishing.
  const extra = await envFileStore('node', 'node-extra-ca', 'NODE_EXTRA_CA_CERTS', 'adds-to', lookup);
  return [bundled, extra];
}

/**
 * The bundle Go's `crypto/x509` falls back to on linux: the first existing row
 * of the same `LINUX_CA_BUNDLE_PATHS` the OS reference reads, which is what
 * makes the cross-check of the two sound - one table, so the modeled Go set
 * cannot drift from the reference (see that table's own comment). Exported
 * with `paths` as an argument for the same reason the OS reader's bundle read
 * is: the real rows are absolute host paths, and a test that statted them
 * would pass on a linux runner and fail on a Windows one.
 */
export async function goSystemBundleStore(
  paths: readonly string[],
  maxBytes: number,
): Promise<RuntimeStoreOutcome> {
  const kind = 'go-system-bundle';
  const combines = 'standalone';
  const tried: string[] = [];
  for (const path of paths) {
    tried.push(path);
    // A row that is not there is the ordinary case; the next row is the answer.
    if (!(await exists(path))) continue;
    const contents = await readPemFile(path, maxBytes);
    return outcome('go', { kind, combines, locator: path, searched: capped(tried), ...contents });
  }
  // No locator: there is no file to name (the certifi rule, for the same reason).
  return outcome('go', { kind, combines, searched: capped(paths), failure: 'not-found' });
}

/**
 * Go: the two OpenSSL variables; on darwin and win32 - where Go calls the
 * platform verifier rather than reading a bundle - a row saying so; on linux
 * the system bundle Go actually reads. Emitting a missing-root finding for Go
 * on the verifier platforms would be the tool lying on two of its three
 * targets, so the reader names the behaviour rather than leaving the
 * cross-check to infer it - and on linux it reads the bundle so the
 * cross-check has real contents to judge, not an assertion to trust.
 */
async function goStores(lookup: Lookup): Promise<RuntimeStoreOutcome[]> {
  const file = await envFileStore('go', 'go-ssl-cert-file', 'SSL_CERT_FILE', 'replaces', lookup);
  const dir = await certDirStore('go', lookup);
  const overridden = envValue(lookup.env, 'SSL_CERT_FILE') !== null || envValue(lookup.env, 'SSL_CERT_DIR') !== null;
  const usesVerifier = lookup.platform === 'darwin' || lookup.platform === 'win32';
  if (!overridden && usesVerifier) {
    return [file, dir, outcome('go', { kind: 'platform-verifier', combines: 'standalone' })];
  }
  if (!overridden && lookup.platform === 'linux') {
    return [file, dir, await goSystemBundleStore(LINUX_CA_BUNDLE_PATHS, lookup.maxBytes)];
  }
  return [file, dir];
}

/** Python: the two variables `requests` and `ssl` read, plus certifi on disk. */
async function pythonStores(lookup: Lookup): Promise<RuntimeStoreOutcome[]> {
  return [
    await envFileStore('python', 'python-ssl-cert-file', 'SSL_CERT_FILE', 'replaces', lookup),
    await envFileStore('python', 'python-requests-ca-bundle', 'REQUESTS_CA_BUNDLE', 'replaces', lookup),
    ...(await certifiStores(lookup)),
  ];
}

export const runtimeStoreReader: RuntimeStoreReader = {
  /**
   * The stores for each requested runtime, in the order they were requested.
   *
   * Every branch below returns at least one outcome unconditionally - that is
   * how the postcondition holds, rather than by a sweep at the end that would
   * paper over a branch which had quietly returned nothing. Reads are
   * sequential: there are a handful of them, they are `stat`s and small files,
   * and a concurrent fan-out over a customer's home directory would trade
   * nothing for a less predictable I/O pattern.
   */
  async read(
    runtimes: readonly Runtime[],
    options: { env: NodeJS.ProcessEnv; platform: NodeJS.Platform; maxBytes: number },
  ): Promise<readonly RuntimeStoreOutcome[]> {
    const lookup: Lookup = { platform: options.platform, env: options.env, maxBytes: options.maxBytes };
    const outcomes: RuntimeStoreOutcome[] = [];
    for (const runtime of runtimes) {
      switch (runtime) {
        case 'node':
          outcomes.push(...(await nodeStores(lookup)));
          break;
        case 'go':
          outcomes.push(...(await goStores(lookup)));
          break;
        case 'python':
          outcomes.push(...(await pythonStores(lookup)));
          break;
        case 'java':
          outcomes.push(...(await javaStores(lookup)));
          break;
      }
    }
    return outcomes;
  },
};
