import { parentPort } from 'node:worker_threads';
import { evaluatePac } from './pac.ts';
import type { PacContext, PacVerdict } from './pac.ts';

/**
 * The Worker-thread entry point for one PAC evaluation (M2, ADR-0017).
 *
 * `vm`'s `timeout` option bounds synchronous execution only - it does not
 * bound a hostile script that keeps the event loop alive with
 * microtasks (`Promise.resolve().then(loop)`) or `async`/`await` recursion
 * (both measured to escape `timeout` entirely on this repo's Node - the
 * `vm` call returns a normal verdict in ~1ms and `timeout` never fires; the
 * starvation lands on the host's event loop afterwards. See ADR-0017).
 * `pac-sandbox.ts` (the caller of this file) is the thing that actually
 * bounds that: it races this worker's response against a wall-clock
 * watchdog and calls `worker.terminate()` on timeout, which - unlike
 * `vm`'s in-process `timeout` - kills a thread regardless of what kind of
 * loop it is stuck in.
 *
 * This file does none of the hardening itself: `evaluatePac` is imported
 * and called completely unchanged (ADR-0011's six measures still apply
 * inside it), and this file's only job is the message plumbing to run that
 * call on a thread the caller can kill from outside.
 *
 * One request per instantiation, no request-id correlation, no queue: the
 * caller spawns a fresh worker per `evaluate()` call and terminates it
 * immediately after (razor pass, see ADR-0017's "alternatives considered" -
 * at most one or two PAC evaluations happen per portcall run in practice).
 */

interface PacWorkerRequest {
  url: string;
  host: string;
  ctx: PacContext;
  timeoutMs: number;
}

interface PacWorkerResponse {
  verdict: PacVerdict;
}

if (parentPort === null) {
  throw new Error('pac-worker.ts must run inside a worker_threads Worker');
}

parentPort.once('message', (message: PacWorkerRequest) => {
  const verdict = evaluatePac(message.url, message.host, message.ctx, message.timeoutMs);
  const response: PacWorkerResponse = { verdict };
  parentPort?.postMessage(response);
  // Invariant (ADR-0019): exit synchronously, same tick, nothing async in
  // between. A hostile PAC script's dangling `import()` rejection handler
  // (gadget 7) only runs once this frame yields to the event loop's
  // microtask queue - process.exit() prevents that from ever happening.
  // Moving this behind .then/setImmediate/await reopens the escape.
  process.exit(0);
});
