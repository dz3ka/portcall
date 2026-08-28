import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { LINUX_CA_BUNDLE_PATHS, OS_TRUSTSTORE_COMMANDS } from '../../src/net/os-truststore.ts';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');
const READER = 'net/os-truststore.ts';

/**
 * ADR-0033. Portcall executes **only** binaries at a fixed absolute path, from
 * a pinned argument list, and this is where that stops being prose.
 *
 * It exists because M4 had to narrow two patterns in
 * `no-credential-access.test.ts` (`/keychain/i` and `/security find-/i`) to let
 * the OS trust-store reader name the platform's own certificate-listing
 * command. ADR-0025 forbids weakening a guardrail to buy a green run, so the
 * amendment had to be a net strengthening, and this file is the strengthening:
 *
 *   before  "no file in src/ says keychain"
 *   after   "here is the complete, byte-pinned list of every external process
 *            portcall may start, exactly one file may start them, exactly one
 *            file may name them, and no file anywhere may name a keystore
 *            password"
 *
 * The pinned table is asserted element by element on purpose. Changing one
 * character of one argument fails CI and lands in the diff a reviewer reads,
 * which is the only check that would catch a later edit interpolating a
 * caller-supplied path into an argv - every text pattern in
 * `no-credential-access.test.ts` would stay silent for that.
 */

/**
 * The command table exactly as it must be. Written out, not imported and
 * reformatted. `timeoutMs` is pinned here for the same reason every other field
 * is (ADR-0037): it is the healthy-read ceiling for that store on that
 * platform, so raising it - which is how a hung read gets accommodated instead
 * of reported - has to arrive as a diff a reviewer reads.
 */
const EXPECTED_COMMANDS = [
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
    timeoutMs: 5_000,
  },
];

const CHILD_PROCESS_IMPORT = /from\s+['"]node:child_process['"]|require\(\s*['"]node:child_process['"]\s*\)/;

/**
 * Names only the reader may say. `security find-` is here rather than in
 * `no-credential-access.test.ts` because it is not a credential pattern: it is
 * the *process-start* surface, and the question is which file may name it, not
 * whether the string is allowed to exist.
 */
const READER_ONLY_NAMES: readonly RegExp[] = [
  /\bcertutil\b/i,
  /powershell/i,
  /Cert:\\/i,
  /security find-/i,
  // The two exported per-store entry points. A module that called them could
  // pass a `TrustStoreCommand` of its own, which is exactly the injectable
  // surface the pinned table removes.
  /\breadOneStore\b/,
  /\breadLinuxCaBundle\b/,
];

/**
 * The region of `os-truststore.ts` the table lives in, delimited by comment
 * markers in the source. Nothing in it may be built at run time: no template
 * substitution, no concatenation, no environment read.
 */
const REGION_START = '// --- BEGIN PINNED COMMAND TABLE ---';
const REGION_END = '// --- END PINNED COMMAND TABLE ---';

interface Buildable {
  pattern: RegExp;
  why: string;
}

const BUILT_AT_RUNTIME: readonly Buildable[] = [
  { pattern: /\$\{/, why: 'a template substitution could carry a runtime value into an argv' },
  { pattern: /['"`]\s*\+|\+\s*['"`]/, why: 'string concatenation could carry a runtime value into an argv' },
  { pattern: /\.concat\s*\(/, why: 'concat() could carry a runtime value into an argv' },
  { pattern: /\bprocess\.env\b/, why: 'the environment is attacker-influenceable; an argv may not read it' },
  { pattern: /\bString\.raw\b/, why: 'a raw template is still a template' },
];

/** Offenders in the table region. Exported so the negative cases below use the real scan. */
export function scanTableRegion(region: string): string[] {
  return BUILT_AT_RUNTIME.filter(({ pattern }) => pattern.test(region)).map(
    ({ pattern, why }) => `${pattern.toString()} - ${why}`,
  );
}

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      yield full;
    }
  }
}

async function sources(): Promise<{ rel: string; text: string }[]> {
  const files: { rel: string; text: string }[] = [];
  for await (const file of walk(SRC_ROOT)) {
    files.push({ rel: relative(SRC_ROOT, file).replace(/\\/g, '/'), text: await readFile(file, 'utf8') });
  }
  return files;
}

async function tableRegion(): Promise<string> {
  const text = await readFile(join(SRC_ROOT, 'net', 'os-truststore.ts'), 'utf8');
  const start = text.indexOf(REGION_START);
  const end = text.indexOf(REGION_END);
  expect(start, `${READER} has lost its ${REGION_START} marker`).toBeGreaterThanOrEqual(0);
  expect(end, `${READER} has lost its ${REGION_END} marker`).toBeGreaterThan(start);
  return text.slice(start, end);
}

describe('subprocess boundary guardrail', () => {
  it('starts a process from exactly one file, and it is the trust-store reader', async () => {
    const importers = (await sources())
      .filter((file) => CHILD_PROCESS_IMPORT.test(file.text))
      .map((file) => file.rel);
    expect(importers).toEqual([READER]);
  });

  it('runs exactly this table of commands, argument for argument', () => {
    expect(OS_TRUSTSTORE_COMMANDS).toEqual(EXPECTED_COMMANDS);
    expect(LINUX_CA_BUNDLE_PATHS).toEqual([
      '/etc/ssl/certs/ca-certificates.crt',
      '/etc/pki/tls/certs/ca-bundle.crt',
      '/etc/ssl/ca-bundle.pem',
      '/etc/pki/tls/cacert.pem',
      '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
      '/etc/ssl/cert.pem',
    ]);
  });

  it('pins every bundle path as a frozen absolute POSIX path', () => {
    // The rows are read as files, never resolved against anything, so a
    // relative row would resolve against the working directory - and the
    // freeze is what a `readonly` type does not do at run time.
    expect(Object.isFrozen(LINUX_CA_BUNDLE_PATHS)).toBe(true);
    for (const path of LINUX_CA_BUNDLE_PATHS) {
      expect(typeof path, 'every bundle path must be a string literal').toBe('string');
      expect(path, `${path} must be an absolute POSIX path`).toMatch(/^\//);
    }
  });

  it('names an absolute file for every command, never a name PATH would resolve', () => {
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      expect(command.file, `${command.kind} must name an absolute path`).toMatch(/^(?:\/|[A-Z]:\\)/);
    }
  });

  it('freezes the table, so a run-time caller cannot rewrite an argument', () => {
    expect(Object.isFrozen(OS_TRUSTSTORE_COMMANDS)).toBe(true);
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      expect(Object.isFrozen(command)).toBe(true);
      expect(Object.isFrozen(command.argv)).toBe(true);
    }
  });

  it('builds no part of the table at run time', async () => {
    const region = await tableRegion();
    // Not vacuous: the region really is the table, not an empty slice.
    expect(region).toContain('/usr/bin/security');
    expect(region).toContain('powershell.exe');
    expect(scanTableRegion(region)).toEqual([]);
  });

  it.each([
    "argv: ['find-certificate', '-a', '-p', `${keychain}`],",
    "argv: ['find-certificate', '-a', '-p', '/Library/Keychains/' + name],",
    "argv: ['-Command', base.concat(suffix)],",
    "file: process.env.COMSPEC,",
    'argv: [String.raw`-Command`],',
  ])('catches a table that builds an argument at run time: %s', (line) => {
    expect(scanTableRegion(line).length).toBeGreaterThan(0);
  });

  it('lets no module but the reader name a certificate tool or a per-store entry point', async () => {
    const offenders: string[] = [];
    for (const file of await sources()) {
      if (file.rel === READER) continue;
      for (const pattern of READER_ONLY_NAMES) {
        if (pattern.test(file.text)) offenders.push(`${file.rel}: matched ${pattern.toString()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('would catch a second file naming one of those tools', () => {
    const offending = "const listing = 'certutil -store Root';";
    expect(READER_ONLY_NAMES.some((pattern) => pattern.test(offending))).toBe(true);
  });
});
