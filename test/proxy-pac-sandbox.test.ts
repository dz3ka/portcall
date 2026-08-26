import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createPacSandbox } from '../src/probes/proxy/pac-sandbox.ts';
import type { PacContext } from '../src/probes/proxy/pac.ts';

/**
 * The Worker half of PAC evaluation. `test/proxy-pac.test.ts` covers what
 * `evaluatePac` decides; this file covers the thing that decides how long it
 * is allowed to take, using the same `test/fixtures/pac/*.js` script text.
 *
 * Two of those fixtures are the reason this machinery exists at all: `vm`'s
 * `timeout` bounds synchronous execution only, so a script that spins on
 * microtasks or `async` recursion answers the call and then starves the event
 * loop of the thread that ran it for good. That failure cannot be asserted
 * from inside the process it happens to - it *is* the process hanging - so
 * the last cases run it in a child process
 * (`test/fixtures/pac-dos-harness.ts`) and assert the child has to be killed
 * without the sandbox and exits on its own with it.
 */

const PAC_DIR = join(import.meta.dirname, 'fixtures', 'pac');
const HARNESS = join(import.meta.dirname, 'fixtures', 'pac-dos-harness.ts');
const REQUEST_URL = 'https://api.example.com/';
const REQUEST_HOST = 'api.example.com';
/** Short on purpose: the watchdog fires at this plus a fixed 250ms grace, and every case below waits for it. */
const TIMEOUT_MS = 200;
/** A settled `evaluate()` must land inside this - watchdog (450ms) plus room for a Worker spawn on a loaded CI box. */
const SETTLE_BUDGET_MS = 5000;
/** Long enough that a child which is going to print `alive` has, short enough that a hung one is cheap. */
const HARNESS_KILL_MS = 2500;

const HOSTILE_ASYNC_FIXTURES = ['hostile-microtask-loop.js', 'hostile-async-recursion.js'];

async function ctxFor(fixture: string): Promise<PacContext> {
  return {
    scriptText: await readFile(join(PAC_DIR, fixture), 'utf8'),
    resolvedTarget: { host: REQUEST_HOST, addresses: ['93.184.216.34'] },
    myAddress: '10.0.0.5',
    now: new Date('2026-08-25T00:00:00Z'),
  };
}

interface HarnessRun {
  stdout: string;
  killed: boolean;
}

/**
 * `killed` rather than a thrown error: a child that has to be killed is the
 * expected outcome of one of these runs, not a test failure. Anything else
 * non-zero (a crash, a bad argument) still rejects, so a broken harness
 * cannot masquerade as a proven hang.
 */
function runHarness(mode: 'in-process' | 'sandbox', fixture: string): Promise<HarnessRun> {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [HARNESS, mode, fixture], { timeout: HARNESS_KILL_MS }, (error, stdout) => {
      if (error === null) {
        resolve({ stdout, killed: false });
        return;
      }
      if (error.killed === true) {
        resolve({ stdout, killed: true });
        return;
      }
      reject(new Error(`pac-dos-harness ${mode} ${fixture} failed: ${error.message}`));
    });
  });
}

describe('createPacSandbox: verdicts pass through unchanged', () => {
  it('returns the parsed proxy a normal script routes to', async () => {
    const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor('always-proxy.js'), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: 'proxy.corp.internal', port: 8080 });
  });

  it('returns direct for an always-DIRECT script', async () => {
    const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor('always-direct.js'), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('returns error for a script that does not parse, exactly as an in-thread evaluation would', async () => {
    const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor('syntax-error.js'), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });
});

describe('createPacSandbox: hostile scripts', () => {
  it('bounds a synchronous infinite loop and answers error', async () => {
    const started = Date.now();
    const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor('hostile-infinite-loop.js'), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
    expect(Date.now() - started).toBeLessThan(SETTLE_BUDGET_MS);
  });

  it.each(HOSTILE_ASYNC_FIXTURES)('settles %s and leaves this thread able to run a timer', async (fixture) => {
    const started = Date.now();
    const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor(fixture), TIMEOUT_MS);
    expect(Date.now() - started).toBeLessThan(SETTLE_BUDGET_MS);
    expect(verdict.kind).not.toBe('unresolved');

    // The starved thread was the Worker's, and it has been terminated, so this
    // one still schedules and runs a timer. Evaluate the same script in-thread
    // and this line is unreachable for the rest of the process - which is what
    // the child-process cases at the bottom of this file demonstrate.
    const before = Date.now();
    await delay(20);
    expect(Date.now() - before).toBeLessThan(SETTLE_BUDGET_MS);
  });

  it('answers error when the worker never responds, on its own clock', async () => {
    // A worker module that answers nothing at all: the only path left is the
    // wall-clock watchdog, which no PAC script can influence.
    const silentWorker = new URL('data:text/javascript,/* never answers */');
    const started = Date.now();
    const verdict = await createPacSandbox(silentWorker).evaluate(
      REQUEST_URL,
      REQUEST_HOST,
      await ctxFor('always-proxy.js'),
      TIMEOUT_MS,
    );
    const elapsed = Date.now() - started;
    expect(verdict).toEqual({ kind: 'error' });
    expect(elapsed).toBeGreaterThanOrEqual(TIMEOUT_MS);
    expect(elapsed).toBeLessThan(SETTLE_BUDGET_MS);
  });
});

describe('createPacSandbox: the worker itself fails to start', () => {
  it('answers error when the worker module does not exist', async () => {
    const missing = new URL('./no-such-pac-worker.ts', import.meta.url);
    const verdict = await createPacSandbox(missing).evaluate(REQUEST_URL, REQUEST_HOST, await ctxFor('always-proxy.js'), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });

  it('answers error when constructing the worker throws outright', async () => {
    // `new Worker()` rejects a URL scheme it cannot load synchronously, which
    // is the one construction failure that never reaches an `error` event.
    const unloadable = new URL('unsupported-scheme:pac-worker');
    const verdict = await createPacSandbox(unloadable).evaluate(
      REQUEST_URL,
      REQUEST_HOST,
      await ctxFor('always-proxy.js'),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'error' });
  });
});

describe('the denial of service this sandbox exists for, in a child process', () => {
  it.each(HOSTILE_ASYNC_FIXTURES)('%s wedges an in-thread evaluation permanently', async (fixture) => {
    const run = await runHarness('in-process', fixture);

    // The evaluation *answered* - `vm`'s timeout never fired, because nothing
    // about this script is synchronous - and then the process stopped making
    // progress and had to be killed.
    expect(run.stdout).toContain('evaluated:');
    expect(run.stdout).not.toContain('alive');
    expect(run.killed).toBe(true);
  });

  it.each(HOSTILE_ASYNC_FIXTURES)('%s is contained by the sandbox', async (fixture) => {
    const run = await runHarness('sandbox', fixture);

    expect(run.stdout).toContain('evaluated:');
    expect(run.stdout).toContain('alive');
    expect(run.killed).toBe(false);
  });
});
