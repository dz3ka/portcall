import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { derToPem, pemBlocks } from '../src/net/pem.ts';
import {
  LINUX_CA_BUNDLE_PATHS,
  MAX_STORE_OUTPUT_BYTES,
  OS_TRUSTSTORE_COMMANDS,
  SUBPROCESS_TIMEOUT_MS,
  osTrustStoreReader,
  readLinuxCaBundle,
  readOneStore,
} from '../src/net/os-truststore.ts';
import type { TrustStoreCommand, TrustStoreOutcome } from '../src/net/types.ts';
import { syntheticCert } from './helpers/synthetic-chain.ts';

/**
 * The OS trust-store seam (M4, ADR-0032/ADR-0033). Two things are under test
 * here and they are deliberately separated:
 *
 * 1. the **kill paths** - a missing binary, a child that floods stdout, a child
 *    that never exits, a fired run signal - exercised against `process.execPath`
 *    with a literal `-e` script, because they are properties of the spawn
 *    boundary and not of any one platform's certificate tool;
 * 2. the **real platform read**, run for whatever platform the suite is on, so
 *    the win32 branch is genuinely executed on Windows and the darwin branch on
 *    macOS rather than mocked into always passing.
 *
 * No fixture here is presented as a recording of a real platform tool. The PEM
 * text the parser tests consume is minted in-process by
 * `test/helpers/synthetic-chain.ts` under a key that dies with the process. The
 * macOS `security find-certificate -a -p` output shape is still **unmeasured**
 * (plan R2): `test/fixtures/truststore/record-stores.ts` is what records it, on
 * a real macOS runner, and until that runs the `pem-stream` parser is tested
 * against synthetic input only. Writing a hand-authored "macOS fixture" would
 * make that gap invisible, so there is not one.
 */

const RUN = new AbortController();

/** A never-fired signal, for the cases that are not about aborting. */
function quiet(): AbortSignal {
  return RUN.signal;
}

/** One command that runs `node -e <script>`; the file is absolute by construction. */
function nodeCommand(script: string, format: 'pem-stream' | 'base64-der-lines'): TrustStoreCommand {
  return {
    platform: process.platform,
    kind: 'linux-ca-bundle',
    file: process.execPath,
    argv: ['-e', script],
    format,
  };
}

const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

async function twoSyntheticPems(): Promise<string[]> {
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + YEAR_MS);
  const first = await syntheticCert({
    subject: 'CN=Portcall Synthetic Root A',
    issuer: 'CN=Portcall Synthetic Root A',
    notBefore,
    notAfter,
  });
  const second = await syntheticCert({
    subject: 'CN=Portcall Synthetic Root B',
    issuer: 'CN=Portcall Synthetic Root B',
    notBefore,
    notAfter,
  });
  return [derToPem(first), derToPem(second)];
}

describe('pem', () => {
  it('wraps DER as a PEM block the parser reads back byte-identically', async () => {
    const [pem] = await twoSyntheticPems();
    expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n/);
    expect(pem).toMatch(/-----END CERTIFICATE-----\n$/);
    for (const line of (pem ?? '').split('\n').slice(1, -2)) expect(line.length).toBeLessThanOrEqual(64);
    expect(pemBlocks(pem ?? '')).toEqual([pem]);
  });

  it('canonicalises CRLF, indentation and surrounding prose to the same block', async () => {
    const [pem] = await twoSyntheticPems();
    const messy = `Certificate:\n  subject=/CN=whatever\n${(pem ?? '').replace(/\n/g, '\r\n')}trailing noise\n`;
    expect(pemBlocks(messy)).toEqual([pem]);
  });

  it('returns every certificate in a concatenated bundle, in order', async () => {
    const pems = await twoSyntheticPems();
    expect(pemBlocks(pems.join(''))).toEqual(pems);
  });

  it('never returns a block that is not a certificate', async () => {
    const [pem] = await twoSyntheticPems();
    const withKey = `-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n${pem ?? ''}`;
    expect(pemBlocks(withKey)).toEqual([pem]);
  });

  it('drops a block whose body is not base64 rather than passing garbage on', () => {
    expect(pemBlocks('-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n')).toEqual([]);
    expect(pemBlocks('')).toEqual([]);
    expect(pemBlocks('-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n')).toEqual([]);
  });
});

describe('os trust store command table', () => {
  it('names an absolute file and only string-literal arguments', () => {
    expect(OS_TRUSTSTORE_COMMANDS.length).toBeGreaterThan(0);
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      expect(command.file).toMatch(/^(?:\/|[A-Z]:\\)/);
      for (const argument of command.argv) expect(typeof argument).toBe('string');
    }
  });

  it('is frozen all the way down, so no caller can rewrite an argument', () => {
    expect(Object.isFrozen(OS_TRUSTSTORE_COMMANDS)).toBe(true);
    for (const command of OS_TRUSTSTORE_COMMANDS) {
      expect(Object.isFrozen(command)).toBe(true);
      expect(Object.isFrozen(command.argv)).toBe(true);
    }
  });

  it('reads the Linux bundle with no subprocess at all', () => {
    expect(LINUX_CA_BUNDLE_PATHS.length).toBeGreaterThan(0);
    expect(OS_TRUSTSTORE_COMMANDS.some((command) => command.platform === 'linux')).toBe(false);
  });
});

describe('os trust store reader kill paths', () => {
  it('yields reader-missing for a file that is not there, and never throws', async () => {
    const missing = join(process.cwd(), 'portcall-no-such-reader-binary');
    const outcome = await readOneStore(
      { platform: process.platform, kind: 'linux-ca-bundle', file: missing, argv: ['-a'], format: 'pem-stream' },
      { signal: quiet(), timeoutMs: SUBPROCESS_TIMEOUT_MS },
    );
    expect(outcome.failure).toBe('reader-missing');
    expect(outcome.code).toBe('ENOENT');
    expect(outcome.pems).toEqual([]);
  });

  it('kills a child that floods stdout and yields output-too-large', async () => {
    const script = `const chunk = 'A'.repeat(1024 * 1024); for (let i = 0; i < 16; i += 1) process.stdout.write(chunk);`;
    const outcome = await readOneStore(nodeCommand(script, 'pem-stream'), { signal: quiet(), timeoutMs: 30_000 });
    expect(outcome.failure).toBe('output-too-large');
    expect(outcome.pems).toEqual([]);
    expect(MAX_STORE_OUTPUT_BYTES).toBe(4 * 1024 * 1024);
  });

  it('kills a child that never exits at the caller timeout', async () => {
    const started = Date.now();
    const outcome = await readOneStore(nodeCommand('setInterval(() => {}, 1000);', 'pem-stream'), {
      signal: quiet(),
      timeoutMs: 300,
    });
    expect(outcome.failure).toBe('timeout');
    expect(outcome.code).toBe('signal:SIGKILL');
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it('kills the child when the run signal fires, distinguishably from a timeout', async () => {
    const controller = new AbortController();
    setTimeout(() => {
      controller.abort();
    }, 100);
    const outcome = await readOneStore(nodeCommand('setInterval(() => {}, 1000);', 'pem-stream'), {
      signal: controller.signal,
      timeoutMs: 30_000,
    });
    expect(outcome.failure).toBe('reader-failed');
    expect(outcome.code).toBe('run-signal');
  });

  it('reports a non-zero exit as reader-failed with the exit code, never a message', async () => {
    const outcome = await readOneStore(nodeCommand('process.exit(3);', 'pem-stream'), {
      signal: quiet(),
      timeoutMs: SUBPROCESS_TIMEOUT_MS,
    });
    expect(outcome.failure).toBe('reader-failed');
    expect(outcome.code).toBe('exit:3');
  });

  it("never lets the child's stderr reach any field of the outcome", async () => {
    const script = `process.stderr.write('SECRET-STDERR-/Users/someone/private'); process.stdout.write('no certificates here');`;
    const outcome = await readOneStore(nodeCommand(script, 'pem-stream'), {
      signal: quiet(),
      timeoutMs: SUBPROCESS_TIMEOUT_MS,
    });
    expect(outcome.failure).toBe('no-certificates');
    expect(JSON.stringify(outcome)).not.toContain('SECRET-STDERR');
  });
});

describe('os trust store reader formats', () => {
  it('parses a pem-stream child into one entry per certificate', async () => {
    const pems = await twoSyntheticPems();
    const script = `process.stdout.write(${JSON.stringify(pems.join(''))});`;
    const outcome = await readOneStore(nodeCommand(script, 'pem-stream'), { signal: quiet(), timeoutMs: 30_000 });
    expect(outcome.failure).toBeNull();
    expect([...outcome.pems]).toEqual(pems);
  });

  it('parses base64-der-lines into the same PEMs the pem-stream branch produces', async () => {
    const pems = await twoSyntheticPems();
    const lines = pems.map((pem) => pem.split('\n').slice(1, -2).join('')).join('\r\n');
    const script = `process.stdout.write(${JSON.stringify(`${lines}\r\n`)});`;
    const outcome = await readOneStore(nodeCommand(script, 'base64-der-lines'), { signal: quiet(), timeoutMs: 30_000 });
    expect([...outcome.pems]).toEqual(pems);
  });

  it('drops a base64 line that is not base64 instead of minting a bogus certificate', async () => {
    const script = `process.stdout.write('hello, not base64!\\n');`;
    const outcome = await readOneStore(nodeCommand(script, 'base64-der-lines'), { signal: quiet(), timeoutMs: 30_000 });
    expect(outcome.failure).toBe('no-certificates');
    expect(outcome.pems).toEqual([]);
  });
});

describe('linux ca bundle read', () => {
  it('reads the first path that exists and reports it as the locator', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'portcall-truststore-'));
    try {
      const pems = await twoSyntheticPems();
      const bundle = join(dir, 'ca-certificates.crt');
      await writeFile(bundle, pems.join(''), 'utf8');
      const outcome = await readLinuxCaBundle([join(dir, 'absent.crt'), bundle], MAX_STORE_OUTPUT_BYTES);
      expect(outcome.kind).toBe('linux-ca-bundle');
      expect(outcome.locator).toBe(bundle);
      expect(outcome.failure).toBeNull();
      expect([...outcome.pems]).toEqual(pems);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('yields reader-missing when no candidate path exists', async () => {
    const absent = join(process.cwd(), 'portcall-no-such-bundle.crt');
    const outcome = await readLinuxCaBundle([absent], MAX_STORE_OUTPUT_BYTES);
    expect(outcome.failure).toBe('reader-missing');
    expect(outcome.code).toBe('ENOENT');
  });

  it('yields output-too-large rather than reading a bundle past the cap', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'portcall-truststore-'));
    try {
      const bundle = join(dir, 'ca-certificates.crt');
      await writeFile(bundle, 'x'.repeat(4096), 'utf8');
      const outcome = await readLinuxCaBundle([bundle], 1024);
      expect(outcome.failure).toBe('output-too-large');
      expect(outcome.pems).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('os trust store reader on this platform', () => {
  it('returns one outcome per pinned store for the running platform', async () => {
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), timeoutMs: 20_000 });
    expect(outcomes.map((outcome) => outcome.kind)).toEqual(platformKinds());
    for (const outcome of outcomes) assertWellFormed(outcome);
  });

  it('actually reads at least one store on a supported platform', async () => {
    if (platformKinds().length === 0) return;
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), timeoutMs: 20_000 });
    const read = outcomes.filter((outcome) => outcome.failure === null);
    const detail = JSON.stringify(outcomes.map((outcome) => [outcome.kind, outcome.failure, outcome.code]));
    expect(read.length, `no store read on ${process.platform}: ${detail}`).toBeGreaterThan(0);
    for (const outcome of read) {
      expect(outcome.pems.length).toBeGreaterThan(0);
      for (const pem of outcome.pems) expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n/);
    }
  });
});

function platformKinds(): string[] {
  if (process.platform === 'linux') return ['linux-ca-bundle'];
  return OS_TRUSTSTORE_COMMANDS.filter((command) => command.platform === process.platform).map(
    (command) => command.kind,
  );
}

/** `pems` is empty exactly when `failure` is non-null (types.ts), and no field carries prose. */
function assertWellFormed(outcome: TrustStoreOutcome): void {
  expect(outcome.pems.length === 0).toBe(outcome.failure !== null);
  expect(outcome.locator).toMatch(/^(?:\/|[A-Z]:\\)/);
  if (outcome.code !== null) expect(outcome.code).toMatch(/^(?:[A-Z][A-Z0-9_]*|exit:\d+|signal:[A-Z0-9]+|run-signal)$/);
}
