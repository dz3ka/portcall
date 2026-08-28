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
 * Measured on Windows 11 (2026-08-28): the pinned PowerShell command returns 41
 * roots in ~0.9 s, one unwrapped base64 DER per line, exit 0, empty stderr. The
 * macOS command's output shape is **not** measured - see
 * `test/fixtures/truststore/record-stores.ts`, which records it from a real
 * runner. Until that has run, the `pem-stream` branch is written against
 * Apple's documentation.
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
  },
  {
    platform: 'darwin',
    kind: 'macos-admin-anchors',
    file: '/usr/bin/security',
    argv: ['find-certificate', '-a', '-p', '/Library/Keychains/System.keychain'],
    locator: '/Library/Keychains/System.keychain',
    format: 'pem-stream',
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
  },
];

/** Read directly, no subprocess. Linux only. First path that exists wins. */
const LINUX_PATHS: readonly string[] = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt'];
// --- END PINNED COMMAND TABLE ---

/** Frozen element by element: a `readonly` type disappears at run time, this does not. */
export const OS_TRUSTSTORE_COMMANDS: readonly TrustStoreCommand[] = Object.freeze(
  COMMAND_TABLE.map((command) => Object.freeze({ ...command, argv: Object.freeze([...command.argv]) })),
);

export const LINUX_CA_BUNDLE_PATHS: readonly string[] = Object.freeze([...LINUX_PATHS]);

export const SUBPROCESS_TIMEOUT_MS = 5_000;
export const MAX_STORE_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * The child's whole environment. `SystemRoot` is what lets PowerShell find its
 * own DLLs, and `PATHEXT` is read by the loader on the same platform; nothing
 * else is passed anywhere, so a customer's `HTTP_PROXY`, `JAVA_TOOL_OPTIONS` or
 * `PSModulePath` cannot change what the reader does.
 */
function minimalEnv(): NodeJS.ProcessEnv {
  if (process.platform !== 'win32') return {};
  const env: NodeJS.ProcessEnv = {};
  const systemRoot = process.env.SystemRoot;
  const pathExt = process.env.PATHEXT;
  if (systemRoot !== undefined) env.SystemRoot = systemRoot;
  if (pathExt !== undefined) env.PATHEXT = pathExt;
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
  const outcome = (failure: TrustStoreFailure | null, code: string | null, pems: readonly string[]): TrustStoreOutcome =>
    ({ kind: command.kind, locator: command.locator, pems, failure, code });

  if (options.signal.aborted) {
    return Promise.resolve(outcome('aborted', 'run-signal', []));
  }

  return new Promise<TrustStoreOutcome>((resolve) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;
    let killed: Killed | null = null;

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
      resolve(outcome(failure, code, pems));
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
  const outcome = (
    locator: string,
    pems: readonly string[],
    failure: TrustStoreFailure | null,
    code: string | null,
  ): TrustStoreOutcome => ({ kind: 'linux-ca-bundle', locator, pems, failure, code });

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
   * abort path for no measurable gain.
   */
  async read(options: { signal: AbortSignal; timeoutMs: number }): Promise<readonly TrustStoreOutcome[]> {
    if (process.platform === 'linux') {
      return [await readLinuxCaBundle(LINUX_CA_BUNDLE_PATHS, MAX_STORE_OUTPUT_BYTES)];
    }
    const outcomes: TrustStoreOutcome[] = [];
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      if (command.platform !== process.platform) continue;
      outcomes.push(await readOneStore(command, options));
    }
    return outcomes;
  },
};
