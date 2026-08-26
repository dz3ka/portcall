import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, unlinkSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Worker } from 'node:worker_threads';
import { createPacSandbox } from '../src/probes/proxy/pac-sandbox.ts';
import { evaluatePac } from '../src/probes/proxy/pac.ts';
import type { PacContext, PacVerdict } from '../src/probes/proxy/pac.ts';

/**
 * The PAC sandbox escape suite.
 *
 * `test/proxy-pac.test.ts` asserts what the evaluator *decides*; this file
 * asserts that a PAC script cannot reach out of the realm it decides in. It
 * exists because two escapes were demonstrated against a previous shape of
 * `pac.ts` and no test in this repo exercised escape at all - which is
 * exactly how they survived a review:
 *
 *   1. `dnsResolve.constructor("return process")()` - the helpers were host
 *      function objects, so `.constructor` was the *host* realm's `Function`,
 *      where `codeGeneration: { strings: false }` (a per-context flag) does
 *      not apply. Returned the live `process`, read `process.env`, wrote a
 *      file.
 *   2. `this.constructor.constructor("return process")()` - the same prize
 *      with every helper deleted: `vm.createContext(hostObject)` contextified
 *      a host object, so the sandbox global's own prototype chain reached the
 *      host realm's `Object.prototype`.
 *   3. (gadget 7, ADR-0019) a `.catch` handler on a dangling `import()` -
 *      `e.constructor.constructor("return process")()` reached the same
 *      `process` as gadget 2, but from a microtask that only runs after
 *      `evaluatePac` has already returned, once the worker's message handler
 *      yields to the event loop. Closed at the worker boundary
 *      (`pac-worker.ts` self-exits before that turn can happen), not inside
 *      this file's sandbox - `evaluatePac`'s own confinement was never the
 *      gap.
 *
 * Every hostile fixture below tries to exfiltrate one planted environment
 * variable into the string it returns, so the pass/fail is unambiguous rather
 * than a judgement about stack traces: if `CANARY` shows up in a verdict, the
 * sandbox is open, and any verdict that routes traffic (`proxy`/`direct`) is
 * already a failure because these scripts have no legitimate answer to give.
 */

const PAC_DIR = join(import.meta.dirname, 'fixtures', 'pac');
const REQUEST_URL = 'https://api.example.com/';
const REQUEST_HOST = 'api.example.com';
const TIMEOUT_MS = 200;

/**
 * Planted in `process.env` for the length of this file and read back by name
 * from inside every fixture. Hostname-shaped on purpose: a successful escape
 * returns `PROXY <CANARY>:8080`, which parses into a *routable* verdict, so a
 * leak cannot hide behind "well, it was unresolved anyway".
 */
const CANARY_VAR = 'PORTCALL_PAC_ESCAPE_CANARY';
const CANARY = 'portcall-escape-canary-9f3c1d';

/** The four string handoff slots `PAC_BOOTSTRAP_SOURCE` deletes before the untrusted script runs. */
const HANDOFF_SLOTS = ['__pacUrl', '__pacHost', '__pacTargetJson', '__pacMyAddress'];

beforeAll(() => {
  process.env[CANARY_VAR] = CANARY;
});

afterAll(() => {
  delete process.env[CANARY_VAR];
});

function baseCtx(scriptText: string): PacContext {
  return {
    scriptText,
    resolvedTarget: { host: REQUEST_HOST, addresses: ['93.184.216.34'] },
    myAddress: '10.0.0.5',
    now: new Date('2026-08-25T00:00:00Z'),
  };
}

async function pacFixture(name: string): Promise<string> {
  return readFile(join(PAC_DIR, name), 'utf8');
}

/**
 * The security floor every hostile fixture has to clear, asserted the same
 * way for all six: the script got no answer this tool would act on, and the
 * planted secret is nowhere in what came back. The `JSON.stringify` check is
 * not redundant with the `kind` check - it is what catches a leak arriving
 * through a field a future `PacVerdict` variant adds.
 */
function expectContained(verdict: PacVerdict): void {
  expect(['error', 'unresolved']).toContain(verdict.kind);
  expect(JSON.stringify(verdict)).not.toContain(CANARY);
}

/**
 * The five gadget fixtures that are safe to run on this thread, with the
 * verdict each is *measured* to produce. Asserting the exact kind on top of
 * `expectContained` is the anti-vacuity guard: `unresolved` means the script
 * compiled, ran its gadget, caught the refusal and reached its own `BLOCKED`
 * return. A fixture that had been gutted, renamed or broken into a syntax
 * error would answer `error` and fail here, instead of passing for the wrong
 * reason.
 *
 * `hostile-escape-dynamic-import.js` is deliberately absent - see the
 * Worker-seam describe block below for the measured reason.
 */
const IN_THREAD_FIXTURES: ReadonlyArray<readonly [string, PacVerdict['kind']]> = [
  ['hostile-escape-helper-constructor.js', 'unresolved'],
  ['hostile-escape-this-constructor.js', 'unresolved'],
  ['hostile-escape-global-proto.js', 'unresolved'],
  ['hostile-escape-error-constructor.js', 'unresolved'],
  ['hostile-escape-object-return.js', 'unresolved'],
];

describe('the canary itself', () => {
  it('is actually planted, so an escape would have something to steal', () => {
    // Without this, every assertion below passes against an open sandbox that
    // simply found nothing in the environment to exfiltrate.
    expect(process.env[CANARY_VAR]).toBe(CANARY);
    expect(CANARY).toMatch(/^[a-z0-9-]+$/);
  });

  it('every hostile fixture actually attempts the exfiltration', async () => {
    const names = [...IN_THREAD_FIXTURES.map(([name]) => name), 'hostile-escape-dynamic-import.js'];
    for (const name of names) {
      const source = await pacFixture(name);
      expect(source, `${name} no longer reads the canary`).toContain(CANARY_VAR);
    }
  });
});

describe('evaluatePac: host-realm escape gadgets', () => {
  it.each(IN_THREAD_FIXTURES)('%s is contained and leaks no environment', async (fixture, expectedKind) => {
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(await pacFixture(fixture)), TIMEOUT_MS);
    expectContained(verdict);
    expect(verdict.kind).toBe(expectedKind);
  });

  it('a successful escape would be visible as a routable verdict, not a silent one', () => {
    // The shape the fixtures return *if* their gadget works, run through the
    // same evaluator as a plain string. This pins the detection mechanism
    // itself: were any fixture above to succeed, it would come back as a
    // `proxy` verdict whose host is the canary, and `expectContained` would
    // fail on both of its assertions rather than neither.
    const scriptText = `function FindProxyForURL(url, host) { return "PROXY ${CANARY}:8080"; }`;
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(scriptText), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: CANARY, port: 8080 });
    expect(JSON.stringify(verdict)).toContain(CANARY);
  });
});

describe('the shape of the sandbox global', () => {
  it('exposes nothing from this realm: every own property belongs to the sandbox', () => {
    // The observable form of "only strings cross the boundary". A host string
    // copies in as a value; a host object or function stays a live handle
    // back here, and that handle is detectable from inside - its
    // `.constructor` is not this realm's `Function`, and its prototype chain
    // does not terminate at this realm's `Object.prototype`. Gadget 1 is
    // exactly that condition holding for `dnsResolve`.
    const scriptText = `
      function FindProxyForURL(url, host) {
        var names = Object.getOwnPropertyNames(globalThis);
        var foreign = [];
        for (var i = 0; i < names.length; i += 1) {
          var value = globalThis[names[i]];
          if (value === null || value === undefined) continue;
          if (typeof value === "function") {
            if (value.constructor !== Function) foreign.push(names[i]);
          } else if (typeof value === "object") {
            var proto = value;
            var native = false;
            while (proto !== null) {
              if (proto === Object.prototype) { native = true; break; }
              proto = Object.getPrototypeOf(proto);
            }
            if (!native) foreign.push(names[i]);
          }
        }
        return foreign.length === 0 ? "DIRECT" : "PROXY foreign-" + foreign.join("-") + ":1";
      }
    `;
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(scriptText), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('has no handoff slots left by the time the untrusted script runs', () => {
    // `getOwnPropertyNames`, not `typeof`: a slot set to `undefined` but still
    // present would pass a `typeof` check and still be a channel. The scan
    // runs at the untrusted script's own top level - the first instruction
    // after the bootstrap - so nothing here depends on `FindProxyForURL`
    // being called at all.
    const scriptText = `
      var leftovers = Object.getOwnPropertyNames(globalThis).filter(function (name) {
        return ${JSON.stringify(HANDOFF_SLOTS)}.indexOf(name) !== -1;
      });
      function FindProxyForURL(url, host) {
        return leftovers.length === 0 ? "DIRECT" : "PROXY leftover-" + leftovers.join("-") + ":1";
      }
    `;
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(scriptText), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('still passes the request url and host in, through the bootstrap and not through a slot', () => {
    // The other half of the previous case: deleting the slots must not have
    // cost the script the two values PAC scripts exist to branch on.
    const scriptText = 'function FindProxyForURL(url, host) { return "PROXY " + host + ":7"; }';
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(scriptText), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: REQUEST_HOST, port: 7 });
  });

  it('keeps the helpers working after confinement (ADR-0012 behaviour unchanged)', () => {
    // Confining the helpers to the sandbox realm is only a fix if they still
    // answer. Three of the eight, chosen because they cover the three kinds
    // of helper: pattern matching, pure string shape, and the one that reads
    // the pre-resolved target.
    const scriptText = `
      function FindProxyForURL(url, host) {
        var matched = shExpMatch(host, "*.example.com");
        var plain = isPlainHostName("intranet") && !isPlainHostName(host);
        var address = dnsResolve(host);
        if (matched && plain && address !== null) return "PROXY " + address + ":8080";
        return "PROXY helpers-broken:1";
      }
    `;
    const verdict = evaluatePac(REQUEST_URL, REQUEST_HOST, baseCtx(scriptText), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: '93.184.216.34', port: 8080 });
  });
});

describe('the escape gadgets through the real createPacSandbox() seam', () => {
  /**
   * The production path, and the one the original repro ran on: a Worker
   * thread whose `process.env` is a copy of this process's, canary included.
   * Confinement has to hold on the thread that actually evaluates a PAC file
   * in a real run, not only in this test file's own thread.
   */
  it.each(['hostile-escape-helper-constructor.js', 'hostile-escape-this-constructor.js'])(
    '%s is contained on the worker thread too',
    async (fixture) => {
      const verdict = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, baseCtx(await pacFixture(fixture)), TIMEOUT_MS);
      expectContained(verdict);
    },
  );

  /**
   * `hostile-escape-dynamic-import.js` runs *only* here, and the reason is
   * measured rather than assumed. On this repo's Node (v24.19.0), without
   * `--experimental-vm-modules`, Node never invokes the user
   * `importModuleDynamically` callback at all: `import("node:fs")` returns a
   * promise and the refusal
   * (`ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG`) arrives from a microtask
   * *after* `evaluatePac` has already returned its verdict, uncaught, taking
   * the thread down with it - verified by running this fixture in a bare
   * `node` process, which printed `unresolved` and then died with exit 1.
   *
   * So the assertion is what is actually true and not a line further:
   * nothing was loaded into the sandbox in time to influence a routing
   * decision (the verdict is not routable and carries no canary), and the
   * blast radius of the late refusal is a Worker the caller terminates - this
   * thread survives it. Asserting a synchronous throw would be asserting a
   * behaviour this runtime does not have; asserting "no module was ever
   * loaded" from outside is not observable, but no callback was invoked, so
   * no module resolution ever began.
   */
  it('contains import("node:fs") and leaves this thread alive', async () => {
    const verdict = await createPacSandbox().evaluate(
      REQUEST_URL,
      REQUEST_HOST,
      baseCtx(await pacFixture('hostile-escape-dynamic-import.js')),
      TIMEOUT_MS,
    );
    expectContained(verdict);

    // The late refusal landed on the Worker, not here: this thread still
    // schedules timers and still evaluates the next script.
    await delay(20);
    const after = await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, baseCtx(await pacFixture('always-direct.js')), TIMEOUT_MS);
    expect(after).toEqual({ kind: 'direct' });
  });

  /**
   * Gadget 7 (ADR-0019): the async continuation gap. Unlike every fixture
   * above, this one's `FindProxyForURL` returns synchronously and cleanly -
   * the attack lives entirely in a `.catch` on a dangling `import()`, which
   * only runs once the worker's message handler yields to the event loop.
   * The fix is `pac-worker.ts` calling `process.exit(0)` immediately after
   * `postMessage`, same tick, so that turn never happens. This can only be
   * observed through the production `createPacSandbox()` seam - a bare
   * `evaluatePac()` call has no worker and no exit, and was never this fix's
   * guarantee.
   */
  it('gadget 7: a rejection handler reached after the reply cannot write outside the working directory', async () => {
    const canaryPath = join(tmpdir(), 'portcall-pac-escape-gadget7.canary');
    if (existsSync(canaryPath)) unlinkSync(canaryPath);

    const verdict = await createPacSandbox().evaluate(
      REQUEST_URL,
      REQUEST_HOST,
      baseCtx(await pacFixture('hostile-escape-async-continuation.js')),
      TIMEOUT_MS,
    );
    // The synchronous decision is unaffected by the fix - only the dangling
    // continuation after it is cut off.
    expect(verdict).toEqual({ kind: 'direct' });

    // MEASURED CAVEAT: this does not actually exercise `pac-worker.ts`'s
    // `process.exit(0)` invariant. `createPacSandbox()`'s own `finish()`
    // (`pac-sandbox.ts:88`) calls `worker.terminate()` synchronously, inside
    // the `message` handler, before this promise resolves - measured against
    // this fixture with `process.exit(0)` removed (20 trials), that wins the
    // race most but not all of the time (17/20; 3/20 still leaked the
    // canary) - a real mitigation, but not a deterministic one, and not
    // dependent on the worker exiting itself. This test stays as
    // defense-in-depth coverage of the production seam as it exists today,
    // but it is not the WP14a regression test: it would be expected to flake,
    // not fail cleanly, with `process.exit(0)` reverted. See the worker-level
    // `describe` block below (ADR-0019) for the test that actually fails
    // without the fix.
    await delay(150);
    expect(existsSync(canaryPath)).toBe(false);
  });
});

describe("gadget 7's worker-level invariant (ADR-0019)", () => {
  /**
   * The test above proves the production seam is safe today, but by a
   * mechanism (`pac-sandbox.ts`'s `terminate()`) that isn't the fix this WP
   * added. This test isolates the actual invariant: `pac-worker.ts` calls
   * `process.exit(0)` in the same tick as `postMessage`, so the dangling
   * `.catch` microtask never gets a turn to run - proven by talking to
   * `pac-worker.ts` directly, bypassing `createPacSandbox()` and its own
   * `terminate()` entirely, and never terminating the worker ourselves until
   * after the assertion.
   */
  it('pac-worker.ts self-exits before the dangling rejection can run, with no caller terminate() involved', async () => {
    const canaryPath = join(tmpdir(), 'portcall-pac-escape-gadget7.canary');
    if (existsSync(canaryPath)) unlinkSync(canaryPath);

    const worker = new Worker(new URL('../src/probes/proxy/pac-worker.ts', import.meta.url));
    try {
      worker.postMessage({
        url: REQUEST_URL,
        host: REQUEST_HOST,
        ctx: baseCtx(await pacFixture('hostile-escape-async-continuation.js')),
        timeoutMs: TIMEOUT_MS,
      });

      // No `terminate()` here: the point is to give the worker's own event
      // loop every chance to run the dangling rejection, and observe that it
      // never gets the turn to do so because `process.exit(0)` already ran.
      await delay(300);
      expect(existsSync(canaryPath)).toBe(false);
    } finally {
      await worker.terminate();
    }
  });
});
