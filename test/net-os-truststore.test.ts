import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { derToPem, pemBlocks } from '../src/net/pem.ts';
import {
  LINUX_CA_BUNDLE_PATHS,
  MAX_STORE_OUTPUT_BYTES,
  MIN_STORE_BUDGET_MS,
  OS_TRUSTSTORE_COMMANDS,
  STORE_BUDGET_RESERVE_MS,
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

/**
 * The budget the kill-path cases hand `readOneStore` directly. It is the
 * test's own number, not a production one: those cases drive a synthetic
 * `node -e` command that is not on the pinned table and therefore has no row
 * budget of its own. Production budgets live on the table rows, and the only
 * thing allowed to choose one is `osTrustStoreReader.read` (ADR-0037).
 */
const KILL_PATH_BUDGET_MS = 5_000;

/**
 * A deadline far enough out that every row gets its whole `timeoutMs`. It has
 * to clear the largest ceiling on the pinned table plus
 * `STORE_BUDGET_RESERVE_MS`, not the ceiling of whichever row this platform
 * happens to read: below that, `storeBudgetMs` clamps the row down and the
 * live reads below stop being a test of the store and become a test of this
 * number.
 */
function generousDeadline(): number {
  return Date.now() + 180_000;
}

/** The pinned budget of the row for `kind`, or `null` if this platform has no such row. */
function rowBudget(kind: string): number | null {
  return OS_TRUSTSTORE_COMMANDS.find((command) => command.kind === kind)?.timeoutMs ?? null;
}

/** One command that runs `node -e <script>`; the file is absolute by construction. */
function nodeCommand(script: string, format: 'pem-stream' | 'base64-der-lines'): TrustStoreCommand {
  return {
    platform: process.platform,
    kind: 'linux-ca-bundle',
    file: process.execPath,
    argv: ['-e', script],
    locator: process.execPath,
    format,
    timeoutMs: KILL_PATH_BUDGET_MS,
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

  it('has a store to read on darwin, win32 and linux, so only another platform reads empty', () => {
    // The postcondition `OsTrustStoreReader.read` states and the probe depends
    // on: an empty array means the platform, never a failed read. Asserted on
    // the table rather than by calling `read()`, which only ever runs one of
    // the three branches on any one runner.
    const rows = (platform: NodeJS.Platform): number =>
      OS_TRUSTSTORE_COMMANDS.filter((command) => command.platform === platform).length;
    expect(rows('darwin')).toBe(2);
    expect(rows('win32')).toBe(1);
    expect(LINUX_CA_BUNDLE_PATHS.length).toBeGreaterThan(0);
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
      {
        platform: process.platform,
        kind: 'linux-ca-bundle',
        file: missing,
        argv: ['-a'],
        locator: missing,
        format: 'pem-stream',
        timeoutMs: KILL_PATH_BUDGET_MS,
      },
      { signal: quiet(), timeoutMs: KILL_PATH_BUDGET_MS },
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

  it('kills the child when the run signal fires, and calls it aborted, not reader-failed', async () => {
    const controller = new AbortController();
    setTimeout(() => {
      controller.abort();
    }, 100);
    const outcome = await readOneStore(nodeCommand('setInterval(() => {}, 1000);', 'pem-stream'), {
      signal: controller.signal,
      timeoutMs: 30_000,
    });
    // Not `reader-failed`: the operator pressed Ctrl-C, which says nothing
    // about whether this machine's trust store can be read (CLAUDE.md).
    expect(outcome.failure).toBe('aborted');
    expect(outcome.code).toBe('run-signal');
  });

  it('reports a non-zero exit as reader-failed with the exit code, never a message', async () => {
    const outcome = await readOneStore(nodeCommand('process.exit(3);', 'pem-stream'), {
      signal: quiet(),
      timeoutMs: KILL_PATH_BUDGET_MS,
    });
    expect(outcome.failure).toBe('reader-failed');
    expect(outcome.code).toBe('exit:3');
  });

  it("never lets the child's stderr reach any field of the outcome", async () => {
    const script = `process.stderr.write('SECRET-STDERR-/Users/someone/private'); process.stdout.write('no certificates here');`;
    const outcome = await readOneStore(nodeCommand(script, 'pem-stream'), {
      signal: quiet(),
      timeoutMs: KILL_PATH_BUDGET_MS,
    });
    expect(outcome.failure).toBe('no-certificates');
    expect(JSON.stringify(outcome)).not.toContain('SECRET-STDERR');
  });
});

/**
 * What the child is allowed to inherit. Asserted through `readOneStore` rather
 * than against `minimalEnv` directly, because the claim is about the process
 * that actually gets started: the child reports what it can see in its own exit
 * code, since nothing else it writes is allowed to reach the outcome.
 */
describe('os trust store reader child environment', () => {
  /** `node -e` that exits with the number of names in `names` it can see. */
  function reportsPresent(names: readonly string[]): TrustStoreCommand {
    const list = JSON.stringify(names);
    return nodeCommand(`process.exit(${list}.filter((n) => process.env[n] !== undefined).length);`, 'pem-stream');
  }

  /** `node -e` that exits with the number of names in `names` it cannot see. */
  function reportsMissing(names: readonly string[]): TrustStoreCommand {
    const list = JSON.stringify(names);
    return nodeCommand(`process.exit(${list}.filter((n) => process.env[n] === undefined).length);`, 'pem-stream');
  }

  it('passes nothing a customer sets, however loudly it is set in this process', async () => {
    // An inherited `PSModulePath` is the sharpest of these: it stops the module
    // providing the `Cert:` drive from loading, so a child that could see one
    // would not read the store at all. Planted here so the test cannot pass by
    // the parent simply not having them.
    const planted = ['PSModulePath', 'HTTP_PROXY', 'JAVA_TOOL_OPTIONS'];
    const saved = new Map(planted.map((name) => [name, process.env[name]]));
    for (const name of planted) process.env[name] = 'planted-by-the-test';
    try {
      const outcome = await readOneStore(reportsPresent(planted), {
        signal: quiet(),
        timeoutMs: KILL_PATH_BUDGET_MS,
      });
      expect(outcome.code, 'a variable the reader must never pass reached the child').toBe(null);
      expect(outcome.failure).toBe('no-certificates');
    } finally {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  it('passes the scratch locations it still forwards, though the cache they were added for is suppressed', async () => {
    // win32 only: everywhere else the child's environment is empty by design.
    // These names arrived on the `ModuleAnalysisCache` rationale and ADR-0040
    // suppressed that cache, so they are now retained on an unmeasured
    // possibility instead (see `minimalEnv`). What this pins is that every one
    // of them this process has still reaches the child - not why.
    if (process.platform !== 'win32') return;
    const expected = ['SystemRoot', 'PATHEXT', 'TEMP', 'TMP', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'ComSpec'];
    const present = expected.filter((name) => process.env[name] !== undefined);
    expect(present.length, 'this Windows host sets none of them, so the test would be vacuous').toBeGreaterThan(0);
    const outcome = await readOneStore(reportsMissing(present), {
      signal: quiet(),
      timeoutMs: KILL_PATH_BUDGET_MS,
    });
    expect(outcome.code, 'a scratch location this process has did not reach the child').toBe(null);
    expect(outcome.failure).toBe('no-certificates');
  });

  it('gives the child a null module-analysis cache path, so PowerShell writes no cache', async () => {
    // win32 only: `PSModuleAnalysisCachePath` is a Windows PowerShell setting,
    // and everywhere else the child's environment is empty by design.
    if (process.platform !== 'win32') return;
    const outcome = await readOneStore(
      nodeCommand("process.exit(process.env.PSModuleAnalysisCachePath === 'NUL' ? 0 : 1);", 'pem-stream'),
      { signal: quiet(), timeoutMs: KILL_PATH_BUDGET_MS },
    );
    expect(outcome.code, 'the child did not get the null cache path').toBe(null);
    expect(outcome.failure).toBe('no-certificates');
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

  it('yields reader-missing for an empty candidate list, naming a path it did look for', async () => {
    // Not reachable through `read()`, which always passes the pinned table -
    // pinned here so that a caller that narrows the list to nothing still gets
    // an outcome with a locator, rather than `undefined` in a finding.
    const outcome = await readLinuxCaBundle([], MAX_STORE_OUTPUT_BYTES);
    expect(outcome.failure).toBe('reader-missing');
    expect(outcome.code).toBe('ENOENT');
    expect(LINUX_CA_BUNDLE_PATHS).toContain(outcome.locator);
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
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: generousDeadline() });
    expect(outcomes.map((outcome) => outcome.kind)).toEqual(platformKinds());
    for (const outcome of outcomes) assertWellFormed(outcome);
    // Per test, not the suite: this one waits on a real store, whose ceiling on
    // win32 is most of a minute on its own. The other suites keep the 60 s
    // default, which is what catches a unit test that has hung.
  }, 120_000);

  /**
   * What `verify` is allowed to claim about a live read, and no more. A store
   * that answers is asserted all the way down to the PEM; a store that runs
   * past its budget is a fact about *this machine* and the milestone's own
   * subject matter, so it passes here and the e2e job (WP7) is where a
   * successful Windows read is asserted against an injected root.
   *
   * Every other failure class still fails: `reader-missing` and `reader-failed`
   * mean the pinned command is wrong for this platform, `no-certificates` means
   * the parser lost the output, and `aborted` means the run signal fired inside
   * `verify`, which nothing here does.
   */
  it('either reads a store or reports it as out of budget - nothing else passes', async () => {
    if (platformKinds().length === 0) return;
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: generousDeadline() });
    const detail = JSON.stringify(
      outcomes.map((outcome) => [outcome.kind, outcome.failure, outcome.code, outcome.budgetMs]),
    );
    expect(outcomes.length, `no outcome on ${process.platform}: ${detail}`).toBeGreaterThan(0);
    for (const outcome of outcomes) {
      assertWellFormed(outcome);
      if (outcome.failure === null) {
        expect(outcome.pems.length, detail).toBeGreaterThan(0);
        for (const pem of outcome.pems) expect(pem).toMatch(/^-----BEGIN CERTIFICATE-----\n/);
        continue;
      }
      expect(outcome.failure, detail).toBe('timeout');
      expect(['signal:SIGKILL', 'budget-exhausted'], detail).toContain(outcome.code);
    }
  }, 120_000);
});

/**
 * The read budget (ADR-0037). It belongs to the pinned row and is clamped by
 * the run's deadline, so there is no caller-supplied number for the constant
 * and the test to drift apart on.
 */
describe('os trust store read budget', () => {
  /** True where `read()` starts a child; on linux it opens a file instead. */
  const spawns = OS_TRUSTSTORE_COMMANDS.some((command) => command.platform === process.platform);

  it('cuts a row budget down to what the run deadline leaves', async () => {
    // 3.5 s minus the 2 s reserve is 1.5 s: under every row ceiling, over the
    // minimum, so the first store is still spawned - with a smaller budget.
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: Date.now() + 3_500 });
    if (!spawns) {
      expect(outcomes.map((outcome) => outcome.budgetMs)).toEqual([null]);
      return;
    }
    const [first] = outcomes;
    expect(first).toBeDefined();
    if (first === undefined) return;
    const ceiling = rowBudget(first.kind);
    expect(ceiling, `${first.kind} has no pinned row budget`).not.toBeNull();
    expect(first.budgetMs).not.toBeNull();
    expect(first.budgetMs ?? 0).toBeGreaterThanOrEqual(MIN_STORE_BUDGET_MS);
    expect(first.budgetMs ?? 0, 'the deadline did not clamp anything').toBeLessThan(ceiling ?? 0);
    // A store the clamp let run either answers or is killed at the cut budget;
    // a later store on the same platform may have nothing left at all.
    for (const outcome of outcomes) {
      expect(outcome.budgetMs ?? 0).toBeLessThan(rowBudget(outcome.kind) ?? 0);
      if (outcome.failure !== null) {
        expect(outcome.failure).toBe('timeout');
        expect(['signal:SIGKILL', 'budget-exhausted']).toContain(outcome.code);
      }
    }
  });

  it('starts no process at all once less than the minimum budget is left', async () => {
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: Date.now() - 1 });
    if (!spawns) {
      expect(outcomes.map((outcome) => outcome.budgetMs)).toEqual([null]);
      return;
    }
    for (const outcome of outcomes) {
      expect(outcome.failure).toBe('timeout');
      expect(outcome.code).toBe('budget-exhausted');
      expect(outcome.budgetMs).toBe(0);
      expect(outcome.pems).toEqual([]);
    }
    expect(STORE_BUDGET_RESERVE_MS).toBeGreaterThan(MIN_STORE_BUDGET_MS);
  });

  it('reports no budget for a sub-minimum budget that is not yet zero', async () => {
    // Lands `effective` inside (0, MIN_STORE_BUDGET_MS): the branch fires, and
    // the value that decided it is not the value the outcome may report.
    const deadline = Date.now() + STORE_BUDGET_RESERVE_MS + MIN_STORE_BUDGET_MS / 2;
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline });
    if (!spawns) {
      expect(outcomes.map((outcome) => outcome.budgetMs)).toEqual([null]);
      return;
    }
    for (const outcome of outcomes) {
      expect(outcome.code).toBe('budget-exhausted');
      expect(outcome.budgetMs, 'a store no child was started for reported a budget').toBe(0);
    }
  });

  /**
   * The elapsed read, which is the number a `timeout` outcome does not carry:
   * `failure: 'timeout'` says "at least the ceiling" and stops there, so a
   * store that missed by a second and one that would never have answered read
   * identically. Asserted as a pair, because the null is load-bearing too - it
   * is what keeps a read that never started out of the elapsed column.
   */
  it('reports how long a read took, and nothing at all where no read was started', async () => {
    const ran = await readOneStore(nodeCommand(`process.stdout.write('nothing');`, 'pem-stream'), {
      signal: quiet(),
      timeoutMs: KILL_PATH_BUDGET_MS,
    });
    expect(ran.readMs, 'a read that ran reported no elapsed time').not.toBeNull();
    expect(ran.readMs ?? -1).toBeGreaterThanOrEqual(0);

    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: Date.now() - 1 });
    if (!spawns) {
      // The linux branch has no budget branch to reach: it opens a file, and
      // it does that whatever the deadline says, so the read did happen.
      for (const outcome of outcomes) expect(outcome.readMs).not.toBeNull();
      return;
    }
    for (const outcome of outcomes) {
      expect(outcome.code).toBe('budget-exhausted');
      expect(outcome.readMs, 'a store no child was started for reported an elapsed read').toBeNull();
    }
  });

  it('lets an already-fired run signal outrank both budget branches', async () => {
    const controller = new AbortController();
    controller.abort();
    const outcomes = await osTrustStoreReader.read({ signal: controller.signal, deadline: Date.now() - 1 });
    if (!spawns) {
      expect(outcomes.map((outcome) => outcome.budgetMs)).toEqual([null]);
      return;
    }
    // "The operator pressed Ctrl-C" is not a claim about this machine's budget,
    // and reporting it as one would be the conflation ADR-0009 forbids.
    for (const outcome of outcomes) {
      expect(outcome.failure).toBe('aborted');
      expect(outcome.code).toBe('run-signal');
      expect(outcome.budgetMs).toBe(0);
    }
  });

  it('gives the Linux bundle no budget, because it starts no process', async () => {
    const absent = join(process.cwd(), 'portcall-no-such-bundle.crt');
    const outcome = await readLinuxCaBundle([absent], MAX_STORE_OUTPUT_BYTES);
    expect(outcome.budgetMs).toBeNull();
    if (process.platform !== 'linux') return;
    const outcomes = await osTrustStoreReader.read({ signal: quiet(), deadline: generousDeadline() });
    expect(outcomes.map((each) => each.budgetMs)).toEqual([null]);
    // The same allowance as the two live reads above, for the same reason: the
    // linux branch here is a real store read. It opens a file rather than
    // starting a child, so it has never come near either budget.
  }, 120_000);
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
  const stores = [...OS_TRUSTSTORE_COMMANDS.map((command) => command.locator), ...LINUX_CA_BUNDLE_PATHS];
  expect(stores, `${outcome.locator} is not a store this build reads`).toContain(outcome.locator);
  if (outcome.code !== null) {
    expect(outcome.code).toMatch(/^(?:[A-Z][A-Z0-9_]*|exit:\d+|signal:[A-Z0-9]+|run-signal|budget-exhausted)$/);
  }
  // Null is the file read's answer and only the file read's: a budget is a
  // statement about a child process, and the linux branch starts none.
  if (outcome.kind === 'linux-ca-bundle') expect(outcome.budgetMs).toBeNull();
  else expect(outcome.budgetMs, `${outcome.kind} reported no budget`).not.toBeNull();
  // Zero is the whole no-spawn signal, so it may not leak onto a read that ran.
  if (outcome.code === 'budget-exhausted') {
    expect(outcome.budgetMs).toBe(0);
    // Nothing ran, so nothing took any time; a 0 here would read as an
    // instantaneous read rather than an absent one.
    expect(outcome.readMs).toBeNull();
  }
  if (outcome.readMs !== null) expect(outcome.readMs).toBeGreaterThanOrEqual(0);
}
