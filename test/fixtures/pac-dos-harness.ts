import { writeSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createPacSandbox } from '../../src/probes/proxy/pac-sandbox.ts';
import { evaluatePac } from '../../src/probes/proxy/pac.ts';
import type { PacContext, PacVerdict } from '../../src/probes/proxy/pac.ts';

/**
 * Child-process harness for the PAC denial-of-service repros in
 * `test/proxy-pac-sandbox.test.ts`. Run as:
 *
 *   node test/fixtures/pac-dos-harness.ts <in-process|sandbox> <fixture.js>
 *
 * It is a separate process because the failure it demonstrates cannot be
 * asserted from inside the process it happens to: `hostile-microtask-loop.js`
 * does not stop `evaluatePac` from *returning* a verdict, it starves the
 * event loop of whichever thread ran it for the rest of that process's life.
 * In `in-process` mode the `alive` line below therefore never prints and the
 * caller has to kill this process; in `sandbox` mode the starved thread is a
 * Worker the sandbox terminates, so both lines print and the process exits 0.
 *
 * Both lines go out through `writeSync`, not `console.log`: stdout to a pipe
 * is flushed by the event loop, which is the exact thing under attack here.
 */

const REQUEST_URL = 'https://api.example.com/';
const REQUEST_HOST = 'api.example.com';
const TIMEOUT_MS = 200;
/** Long enough to be an unambiguous event-loop turn, short enough that a hung child is cheap. */
const ALIVE_DELAY_MS = 50;

const mode = process.argv[2];
const fixture = process.argv[3];
if (mode !== 'in-process' && mode !== 'sandbox') {
  throw new Error('usage: pac-dos-harness.ts <in-process|sandbox> <fixture.js>');
}
if (fixture === undefined) throw new Error('usage: pac-dos-harness.ts <in-process|sandbox> <fixture.js>');

const scriptText = await readFile(join(import.meta.dirname, 'pac', fixture), 'utf8');
const ctx: PacContext = { scriptText, resolvedTarget: null, myAddress: '10.0.0.5', now: new Date() };

const verdict: PacVerdict =
  mode === 'sandbox'
    ? await createPacSandbox().evaluate(REQUEST_URL, REQUEST_HOST, ctx, TIMEOUT_MS)
    : evaluatePac(REQUEST_URL, REQUEST_HOST, ctx, TIMEOUT_MS);

writeSync(1, `evaluated:${verdict.kind}\n`);
setTimeout(() => {
  writeSync(1, 'alive\n');
}, ALIVE_DELAY_MS);
