import { Worker } from 'node:worker_threads';
import type { PacContext, PacVerdict } from './pac.ts';

/**
 * Wall-clock watchdog around one PAC evaluation, on a Worker thread that can
 * be killed from outside it (M2, ADR-0017).
 *
 * `evaluatePac`'s own `vm`'s `timeout` bounds synchronous execution inside
 * the sandbox, but a hostile PAC script can keep the event loop alive past
 * that bound with microtasks (`Promise.resolve().then(loop)`) or
 * `async`/`await` recursion - neither is bounded by `vm`'s `timeout` (see
 * ADR-0017 for the two empirical repros). `pac-worker.ts` runs the
 * unchanged `evaluatePac` call on a separate thread; this module is the
 * caller-side half that races that thread's answer against its own
 * wall-clock timer and can terminate the thread outright, which works
 * regardless of what kind of loop the script is stuck in.
 *
 * Deliberately razor-simple: one `Worker` per `evaluate()` call, spawned and
 * terminated within that one call, no reuse, no pooling, no request-id
 * correlation. See ADR-0017 - at most one or two PAC evaluations happen per
 * portcall run, so per-call spawn/terminate costs nothing worth optimising
 * away, and it mirrors ADR-0011's own "fresh context per call" discipline.
 */

export interface PacSandbox {
  evaluate(url: string, host: string, ctx: PacContext, timeoutMs: number): Promise<PacVerdict>;
}

/** Fixed grace on top of `timeoutMs` for thread-scheduling jitter, not a second script budget. */
const WATCHDOG_GRACE_MS = 250;

/** Same shape `evaluatePac` itself returns for its own internal failures - see `pac.ts`'s `PacVerdict`. */
const ERROR_VERDICT: PacVerdict = { kind: 'error' };

interface PacWorkerRequest {
  url: string;
  host: string;
  ctx: PacContext;
  timeoutMs: number;
}

interface PacWorkerResponse {
  verdict: PacVerdict;
}

/**
 * `pac-worker.ts` is loaded by its own module URL, not bundled: Node's
 * native TypeScript type-stripping runs `.ts` files directly (verified
 * empirically under both plain `node` and vitest for this WP - no
 * transpile step or new dependency needed), and `tsc` (via
 * `tsconfig.build.json`) emits `pac-worker.js` next to this file's own
 * emitted `.js` in `dist/`. Deriving the sibling's extension from this
 * module's own `import.meta.url` - rather than hard-coding `.ts` - is what
 * keeps both the dev (`.ts`) and built (`dist/**\/*.js`) paths working: a
 * hard-coded extension here is a plain string, invisible to
 * `rewriteRelativeImportExtensions` (that option only rewrites import/export
 * specifiers, not `new URL()` string arguments).
 */
function defaultWorkerModuleUrl(): URL {
  const extension = import.meta.url.endsWith('.ts') ? '.ts' : '.js';
  return new URL(`./pac-worker${extension}`, import.meta.url);
}

/**
 * `workerUrl` is the DI seam this module's name promises: production always
 * uses `defaultWorkerModuleUrl()`, and a test can pass a URL that cannot be
 * loaded (e.g. a nonexistent module path) to exercise the worker-construction-
 * failure branch deterministically without needing a real crashing script.
 */
export function createPacSandbox(workerUrl: URL = defaultWorkerModuleUrl()): PacSandbox {
  return {
    evaluate(url, host, ctx, timeoutMs) {
      return new Promise((resolve) => {
        let settled = false;
        let worker: Worker;

        // `finish` is the one place every path below funnels through - success
        // message, watchdog timeout, worker 'error', or an unexpected 'exit' -
        // so `worker.terminate()` runs exactly once per call regardless of
        // which of those fires first. This stands in for a literal
        // try/finally: the Worker's lifecycle here is event-driven, not a
        // single call stack, so there is no synchronous frame for a `finally`
        // block to wrap.
        const finish = (verdict: PacVerdict): void => {
          if (settled) return;
          settled = true;
          clearTimeout(watchdog);
          worker.terminate().catch(() => {
            // `terminate()`'s promise rejecting is not a documented case for
            // a worker that already exists; this only guards against an
            // unhandled rejection crashing the process, never surfaced to
            // the caller either way since `resolve` below already ran.
          });
          resolve(verdict);
        };

        const watchdog = setTimeout(() => {
          finish(ERROR_VERDICT);
        }, timeoutMs + WATCHDOG_GRACE_MS);

        try {
          worker = new Worker(workerUrl);
        } catch {
          clearTimeout(watchdog);
          resolve(ERROR_VERDICT);
          return;
        }

        worker.once('message', (message: PacWorkerResponse) => {
          finish(message.verdict);
        });
        worker.once('error', () => {
          finish(ERROR_VERDICT);
        });
        worker.once('exit', (code: number) => {
          // A nonzero exit *before* a response landed is the worker dying
          // mid-evaluation; `settled` already being true (a message beat the
          // exit, or `finish` already ran from another path) makes this a
          // no-op, including for the `exit` our own `terminate()` triggers.
          if (code !== 0) finish(ERROR_VERDICT);
        });

        const request: PacWorkerRequest = { url, host, ctx, timeoutMs };
        worker.postMessage(request);
      });
    },
  };
}
