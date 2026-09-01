import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { derToPem, normaliseBase64, pemBlocks } from './pem.ts';
import type { OsTrustStoreReader, TrustStoreCommand, TrustStoreFailure, TrustStoreOutcome } from './types.ts';

/**
 * "Which roots does this machine trust?" - answered by enumerating the
 * machine's **public trust anchors** and nothing else (M4, ADR-0032/ADR-0033,
 * SPEC.md 4.2 as amended).
 *
 * This is the only file in `src/` that starts a process, and
 * `test/guardrails/subprocess-boundary.test.ts` is what keeps it that way. The
 * rules it holds this file to are the whole design:
 *
 * - **Absolute paths, never PATH.** Every `file` below is a fixed absolute
 *   path, so nothing a customer's `PATH` contains can stand in for the
 *   platform's own tool.
 * - **A pinned argv of string literals.** No profile value, no environment
 *   value, no certificate field and no hostname is ever interpolated into a
 *   command line, and `shell: false` means there is no shell to inject into.
 *   The guardrail asserts the table element by element, so changing one
 *   argument of one command fails CI and lands in the diff a reviewer reads.
 * - **Public certificates only.** `find-certificate` has no key-emitting mode,
 *   the machine `Root` store holds no keys, and `/etc/ssl/certs` is
 *   world-readable public material. The user's own personal stores - the
 *   macOS user keychain, the Windows CurrentUser and machine `My` stores - are
 *   not named in the table and must never be.
 * - **The child's stderr is drained and thrown away.** A tool's message can
 *   embed a path, a hostname or a user name; only a machine code ever crosses
 *   into an outcome (ADR-0009).
 * - **Nothing here touches `NetworkGuard`.** Reading a local store is not a
 *   network call. Saying so here is what should stop a later reader from
 *   wiring the guard in "for symmetry" and making an offline read look like
 *   egress in the report.
 *
 * On Linux there is no CLI at all: the distribution has already flattened the
 * store into a PEM file, so the reader opens it. That asymmetry is deliberate -
 * shelling out where a file read would do would be a subprocess bought for
 * consistency's sake.
 *
 * Measured on Windows 11 (2026-08-28): the pinned PowerShell command returns one
 * unwrapped base64 DER per line, exit 0, empty stderr - but how much comes back
 * and how long it takes belong to the host, not to the command. A developer
 * laptop answers with 41 roots in ~0.2 s; a windows-latest CI runner answered
 * with 563 roots in 42.9 s under the unamended `minimalEnv()` below. The runner
 * is the figure that governs - it is the machine the milestone is judged on, and
 * a laptop number quoted here once already read as a promise the runner does not
 * keep. The scratch-location passthrough in `minimalEnv()` reduces that cost; it
 * does not remove it. After that amendment the same runner read the store warm
 * in 22.7 s and 29.6 s, and its cold read was still going when a temporary 30 s
 * ceiling clipped it - so the post-amendment cold figure is known only to be
 * >=30 s, and 42.9 s remains the one cold read anyone has measured to
 * completion. That band, not the laptop's fifth of a second, is what the win32
 * row's ceiling is sized against (ADR-0039). The macOS command's output shape
 * is **not** measured - see `test/fixtures/truststore/record-stores.ts`, which
 * records it from a real runner. Until that has run, the `pem-stream` branch is
 * written against Apple's documentation.
 */

// --- BEGIN PINNED COMMAND TABLE ---
// Every value below is a source literal. Nothing may be interpolated,
// concatenated or read from the environment in this region; the
// subprocess-boundary guardrail scans exactly these lines for that.
const COMMAND_TABLE: readonly TrustStoreCommand[] = [
  {
    platform: 'darwin',
    kind: 'macos-system-roots',
    file: '/usr/bin/security',
    argv: ['find-certificate', '-a', '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'],
    locator: '/System/Library/Keychains/SystemRootCertificates.keychain',
    format: 'pem-stream',
    timeoutMs: 5_000,
  },
  {
    platform: 'darwin',
    kind: 'macos-admin-anchors',
    file: '/usr/bin/security',
    argv: ['find-certificate', '-a', '-p', '/Library/Keychains/System.keychain'],
    locator: '/Library/Keychains/System.keychain',
    format: 'pem-stream',
    timeoutMs: 5_000,
  },
  {
    platform: 'win32',
    kind: 'windows-machine-root',
    file: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    argv: [
      '-NoProfile',
      '-NonInteractive',
      '-NoLogo',
      '-Command',
      'Get-ChildItem -Path Cert:\\LocalMachine\\Root | ForEach-Object { [System.Convert]::ToBase64String($_.RawData) }',
    ],
    locator: 'Cert:\\LocalMachine\\Root',
    format: 'base64-der-lines',
    timeoutMs: 60_000,
  },
];

/**
 * Read directly, no subprocess. Linux only. First path that exists wins.
 *
 * The set, and the order, is Go's `crypto/x509` `certFiles`; that is the whole
 * warrant for it, and no row here claims to be any one system's bundle. Two
 * rows was too few: a machine with neither present read as `reader-missing`
 * against a locator naming a file that had never been there, and the probe
 * suppressed every runtime verdict on that machine rather than report one.
 *
 * Borrowing Go's set is sound *conditionally*: this table is the whole of
 * what the OS reference reads on Linux, and `goSystemBundleStore` reads this
 * same constant, so the reference equals the modeled Go store by construction.
 * Real Go's set is this file plus its cert directories - a superset - so a
 * root the reference has is a root Go trusts, and a false `missing-root` is
 * unreachable. If the OS reader ever also reads `/etc/ssl/certs/` as a
 * directory, the reference gains roots no file listed here carries, Go is
 * then measured against a superset of its own trust, and a false
 * `missing-root` becomes reachable. An OS-side certificate-*directory* read
 * must therefore extend Go's set in the same commit that adds it.
 */
const LINUX_PATHS: readonly string[] = [
  '/etc/ssl/certs/ca-certificates.crt',
  '/etc/pki/tls/certs/ca-bundle.crt',
  '/etc/ssl/ca-bundle.pem',
  '/etc/pki/tls/cacert.pem',
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
  '/etc/ssl/cert.pem',
];
// --- END PINNED COMMAND TABLE ---

/** Frozen element by element: a `readonly` type disappears at run time, this does not. */
export const OS_TRUSTSTORE_COMMANDS: readonly TrustStoreCommand[] = Object.freeze(
  COMMAND_TABLE.map((command) => Object.freeze({ ...command, argv: Object.freeze([...command.argv]) })),
);

export const LINUX_CA_BUNDLE_PATHS: readonly string[] = Object.freeze([...LINUX_PATHS]);

/**
 * Left unspent out of the run's remaining time, so that a store read cannot
 * consume the moment the probe needs to turn its outcomes into findings. A run
 * that spends its last millisecond on the read has nothing left to say what it
 * learned.
 */
export const STORE_BUDGET_RESERVE_MS = 2_000;

/**
 * Below this much room, do not start the child: report, do not gamble. A
 * sub-second budget cannot read any store this table names, so spawning into it
 * buys a `signal:SIGKILL` that blames the machine for the run's own clock -
 * `budget-exhausted` is the honest answer and it costs no process.
 */
export const MIN_STORE_BUDGET_MS = 1_000;

export const MAX_STORE_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * What this store may have of what is left. The row's ceiling is the healthy
 * read on that platform; the deadline is the run's, and only ever cuts it
 * down. Never negative: a budget of zero is a number a finding can print
 * (ADR-0037).
 */
function storeBudgetMs(command: TrustStoreCommand, deadline: number): number {
  return Math.max(0, Math.min(command.timeoutMs, deadline - Date.now() - STORE_BUDGET_RESERVE_MS));
}

/**
 * The child's whole environment, and deliberately almost none of one.
 * `SystemRoot` is what lets PowerShell find its own DLLs and `PATHEXT` is read
 * by the loader on the same platform. The six scratch locations after them -
 * `TEMP`, `TMP`, `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `ComSpec` - are here
 * because starving PowerShell of a place to keep its `ModuleAnalysisCache` is
 * not free: with no `LOCALAPPDATA` and no `APPDATA` the cache can be neither
 * read nor written, so every module is re-analysed on every single spawn.
 * Measured on a windows-latest runner (2026-08-28): bare PowerShell startup took
 * 5853 ms under `{SystemRoot, PATHEXT}` against 151 ms under the inherited
 * environment, and the machine-root read took 42859 ms of which
 * `firstByteMs=42776` - 99.8% of the wait is over before the first byte of
 * output exists.
 *
 * That list is the whole amendment, and handing the child the inherited
 * environment instead is **not** the shorter version of it. That was measured
 * too, and it does not read the store at all: exit 1, "Cannot find drive. A
 * drive with the name 'Cert' does not exist", because an inherited
 * `PSModulePath` stops `Microsoft.PowerShell.Security` - the module that
 * provides the `Cert:` drive - from loading. So `PSModulePath` is not an
 * oversight here, it is the point; and `PATH`, `HTTP_PROXY` and
 * `JAVA_TOOL_OPTIONS` stay out for the older reason, that nothing a customer
 * sets may change what the reader does.
 *
 * One thing this function cannot enforce: on Windows, libuv adds a floor of its
 * own to whatever `env` a spawn is given, copying `PATH`, `TEMP`, `USERPROFILE`,
 * `WINDIR` and a handful more from the parent regardless. That is precisely why
 * every `file` in the table above is an absolute path - `PATH` reaches the child
 * whatever is written here, so it must never be the thing that finds the binary.
 */
function minimalEnv(): NodeJS.ProcessEnv {
  if (process.platform !== 'win32') return {};
  const env: NodeJS.ProcessEnv = {};
  const systemRoot = process.env.SystemRoot;
  const pathExt = process.env.PATHEXT;
  const temp = process.env.TEMP;
  const tmp = process.env.TMP;
  const localAppData = process.env.LOCALAPPDATA;
  const appData = process.env.APPDATA;
  const userProfile = process.env.USERPROFILE;
  const comSpec = process.env.ComSpec;
  if (systemRoot !== undefined) env.SystemRoot = systemRoot;
  if (pathExt !== undefined) env.PATHEXT = pathExt;
  if (temp !== undefined) env.TEMP = temp;
  if (tmp !== undefined) env.TMP = tmp;
  if (localAppData !== undefined) env.LOCALAPPDATA = localAppData;
  if (appData !== undefined) env.APPDATA = appData;
  if (userProfile !== undefined) env.USERPROFILE = userProfile;
  if (comSpec !== undefined) env.ComSpec = comSpec;
  return env;
}

/** An errno off an unknown rejection value, or `null`. Never a message. */
function errnoCode(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const { code } = error;
    if (typeof code === 'string') return code;
  }
  return null;
}

/**
 * stdout to PEM strings. Both branches end at `derToPem`, so a certificate read
 * on macOS and the same certificate read on Windows produce the same string -
 * which is what makes the probe's byte comparison meaningful at all.
 */
function parseStdout(format: TrustStoreCommand['format'], stdout: string): readonly string[] {
  if (format === 'pem-stream') return pemBlocks(stdout);
  const pems: string[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const body = normaliseBase64(line);
    if (body === null) continue;
    pems.push(derToPem(Buffer.from(body, 'base64')));
  }
  return pems;
}

/** Why the child was killed, and the machine code that says so. */
interface Killed {
  failure: TrustStoreFailure;
  code: string;
}

/**
 * One store, one child process. Exported because the platform branch in
 * `osTrustStoreReader.read` can only be exercised on the platform it belongs
 * to, while the kill paths - missing binary, flooded stdout, a child that never
 * exits, a fired run signal - are properties of this boundary and must be
 * tested everywhere. No module under `src/` other than this one may call it;
 * the subprocess-boundary guardrail asserts that, because a caller passing its
 * own `TrustStoreCommand` would be the injectable surface the pinned table
 * exists to remove.
 */
export function readOneStore(
  command: TrustStoreCommand,
  options: { signal: AbortSignal; timeoutMs: number },
): Promise<TrustStoreOutcome> {
  // `budgetMs` is the budget this read was given, not the one the row asks
  // for: the caller has already clamped it against the run deadline, and the
  // difference between the two is what tells the probe whether a longer
  // `--timeout` would have helped.
  const outcome = (
    failure: TrustStoreFailure | null,
    code: string | null,
    pems: readonly string[],
    readMs: number | null,
  ): TrustStoreOutcome => ({
    kind: command.kind,
    locator: command.locator,
    pems,
    failure,
    code,
    budgetMs: options.timeoutMs,
    readMs,
  });

  if (options.signal.aborted) {
    // Same rule as the budget branch in `read`: no child, no budget - and no
    // read either, so no elapsed time to report.
    return Promise.resolve({ ...outcome('aborted', 'run-signal', [], null), budgetMs: 0 });
  }

  return new Promise<TrustStoreOutcome>((resolve) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;
    let killed: Killed | null = null;

    // Started before the spawn, not after it: on win32 almost the whole read is
    // over before the first byte exists, so a clock that began at the first
    // chunk would time the cheap part (see `minimalEnv` below).
    const startedAt = Date.now();
    const child = spawn(command.file, [...command.argv], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: minimalEnv(),
    });

    // A timeout and the run's abort both end in SIGKILL, but they stay
    // distinguishable in `failure` as well as `code`: "the store took too long"
    // is a claim about this machine and "the operator pressed Ctrl-C" is not,
    // so they are different tickets (CLAUDE.md) and `aborted` is its own word.
    const kill = (reason: Killed): void => {
      if (killed !== null || settled) return;
      killed = reason;
      chunks.length = 0;
      child.kill('SIGKILL');
    };
    const onAbort = (): void => {
      kill({ failure: 'aborted', code: 'run-signal' });
    };
    const timer = setTimeout(() => {
      kill({ failure: 'timeout', code: 'signal:SIGKILL' });
    }, options.timeoutMs);

    const finish = (failure: TrustStoreFailure | null, code: string | null, pems: readonly string[]): void => {
      // `error` and `close` both fire for a spawn that never started, and a
      // killed child still closes; the first answer is the answer.
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal.removeEventListener('abort', onAbort);
      resolve(outcome(failure, code, pems, Date.now() - startedAt));
    };

    // Drained and retained nowhere: a ring buffer would only be a place for a
    // child's prose to accumulate, and nothing downstream is allowed to read it.
    child.stderr.resume();

    child.stdout.on('data', (chunk: Buffer) => {
      if (killed !== null) return;
      received += chunk.length;
      if (received > MAX_STORE_OUTPUT_BYTES) {
        kill({ failure: 'output-too-large', code: 'signal:SIGKILL' });
        return;
      }
      chunks.push(chunk);
    });

    child.on('error', (error: unknown) => {
      const code = errnoCode(error);
      // ENOENT is the *normal* answer inside a container with no `security`
      // binary, not an error - the probe says "this store could not be read",
      // and nothing about the run has gone wrong.
      finish(code === 'ENOENT' ? 'reader-missing' : 'reader-failed', code, []);
    });

    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      if (killed !== null) {
        finish(killed.failure, killed.code, []);
        return;
      }
      if (signal !== null) {
        finish('reader-failed', `signal:${signal}`, []);
        return;
      }
      if (code !== 0) {
        finish('reader-failed', code === null ? null : `exit:${String(code)}`, []);
        return;
      }
      const pems = parseStdout(command.format, Buffer.concat(chunks).toString('utf8'));
      finish(pems.length === 0 ? 'no-certificates' : null, null, pems);
    });

    options.signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * The Linux bundle, read as a file. Exported for the same reason
 * `readOneStore` is: the branch belongs to one platform and the bounds belong
 * to all of them. `maxBytes` is a parameter rather than the constant so the cap
 * itself is testable without writing a four-megabyte fixture.
 */
export async function readLinuxCaBundle(paths: readonly string[], maxBytes: number): Promise<TrustStoreOutcome> {
  const startedAt = Date.now();
  // Every candidate path is at least stat'ed, so any list at all is a read that
  // happened and has a duration. An empty one is the caller narrowing the list
  // to nothing: no file was opened, and `null` says that where a 0 would claim
  // a read that finished instantly.
  const readMs = (): number | null => (paths.length === 0 ? null : Date.now() - startedAt);
  const outcome = (
    locator: string,
    pems: readonly string[],
    failure: TrustStoreFailure | null,
    code: string | null,
    // No child, no timer, no budget: this branch opens a file, and a budget is
    // a statement about a process. `null` says that, where a `0` would read as
    // "it was given no time".
  ): TrustStoreOutcome => ({ kind: 'linux-ca-bundle', locator, pems, failure, code, budgetMs: null, readMs: readMs() });

  for (const path of paths) {
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch (error) {
      const code = errnoCode(error);
      // Absent means "try the next distribution's path"; unreadable means the
      // bundle is there and something stopped us, which is a different ticket.
      if (code === 'ENOENT') continue;
      return outcome(path, [], 'reader-failed', code);
    }
    if (size > maxBytes) return outcome(path, [], 'output-too-large', null);
    try {
      const pems = pemBlocks(await readFile(path, 'utf8'));
      return outcome(path, pems, pems.length === 0 ? 'no-certificates' : null, null);
    } catch (error) {
      return outcome(path, [], 'reader-failed', errnoCode(error));
    }
  }
  return outcome(paths[0] ?? LINUX_PATHS[0] ?? '/etc/ssl/certs', [], 'reader-missing', 'ENOENT');
}

export const osTrustStoreReader: OsTrustStoreReader = {
  /**
   * Every store this platform has, in table order. A platform that is neither
   * darwin, win32 nor linux has no row and no bundle, so this returns an empty
   * array and the probe reports `unsupported-platform` from it - there is no
   * `TrustStoreKind` that would honestly describe a store that does not exist,
   * and nothing else returns an empty array: on darwin, win32 and linux a
   * failed read is an outcome, so the probe may read emptiness as the platform.
   *
   * The stores are read one at a time. There are at most two, each takes about
   * a second, and running them concurrently would put two children under one
   * abort path for no measurable gain. Serial also means the second store sees
   * the time the first one spent: the budget is recomputed per store, so a
   * keychain that runs long shortens its neighbour rather than overrunning the
   * run.
   */
  async read(options: { signal: AbortSignal; deadline: number }): Promise<readonly TrustStoreOutcome[]> {
    if (process.platform === 'linux') {
      return [await readLinuxCaBundle(LINUX_CA_BUNDLE_PATHS, MAX_STORE_OUTPUT_BYTES)];
    }
    const outcomes: TrustStoreOutcome[] = [];
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      if (command.platform !== process.platform) continue;
      const budgetMs = storeBudgetMs(command, options.deadline);
      // A fired run signal outranks the budget branch: `readOneStore` answers
      // an aborted signal without starting anything either, and "the operator
      // pressed Ctrl-C" is not a claim about this machine's clock.
      if (budgetMs < MIN_STORE_BUDGET_MS && !options.signal.aborted) {
        outcomes.push({
          kind: command.kind,
          locator: command.locator,
          pems: [],
          failure: 'timeout',
          code: 'budget-exhausted',
          // No child was started, so no budget was applied: 0 is the reader's
          // word for "nothing ran" (ADR-0037). The computed value is the reason
          // for the branch, not a budget any process got, and printing it as one
          // would tell an operator a store was read for 800 ms that never ran.
          budgetMs: 0,
          // Nothing was started, so nothing took any time - the same reason.
          readMs: null,
        });
        continue;
      }
      outcomes.push(await readOneStore(command, { signal: options.signal, timeoutMs: budgetMs }));
    }
    return outcomes;
  },
};
