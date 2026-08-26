# ADR-0017: PAC evaluation runs on a terminable Worker thread

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

ADR-0011 item 4 treats `script.runInContext(context, { timeout })` as the
defence against a PAC script that refuses to finish. The M2 review found that
claim too broad: `vm`'s `timeout` bounds *synchronous* execution only, and a
hostile script does not have to loop synchronously.

Measured on this repo's Node (v24.19.0, Windows), with `timeout: 200`:

- `while (true) {}` — throws `ERR_SCRIPT_EXECUTION_TIMEOUT` at 203ms. The
  defence works exactly as ADR-0011 describes.
- `function loop(){ Promise.resolve().then(loop); } loop();` — the call
  **returns normally after 1ms**. Nothing throws. `timeout` does not fire
  late; it never observes the loop at all, because the script's synchronous
  part really did finish. The microtask queue then drains forever on the
  host: a `setTimeout(…, 50)` registered on the next line never fires, and
  the process had to be killed externally after 5s.
- `async function loop(){ await Promise.resolve(); return loop(); } loop();`
  — identical: returns in 1ms, throws nothing, starves the loop afterwards.

So the failure mode is not a slow verdict. `evaluatePac` returns the *correct*
verdict, promptly, and the process it returned into never runs another timer,
never writes the report, and never delivers an exit code. A one-line PAC
script from a WPAD server hangs the whole run. Nothing available inside the
process fixes this: the poisoned queue belongs to the thread that would have
to notice, and V8 offers no in-process way to abandon it.

## Decision

`evaluatePac` runs on a `node:worker_threads` Worker that the caller can kill
from outside, in two new files:

- `src/probes/proxy/pac-worker.ts` — the thread entry point. It does no
  hardening of its own and is only message plumbing: it calls `evaluatePac`
  completely unchanged, so ADR-0011's six measures and ADR-0012's helper
  restrictions still apply inside it.
- `src/probes/proxy/pac-sandbox.ts` — the caller-side half. It races the
  worker's reply against a wall-clock `setTimeout` (`timeoutMs` plus a fixed
  250ms scheduling grace, not a second script budget) and calls
  `worker.terminate()` on **every** exit path: reply, watchdog, worker
  `error`, unexpected `exit`. Timeout yields the same `{ kind: 'error' }`
  verdict `evaluatePac` already returns for its own internal failures, so no
  caller and no finding shape changes.

`terminate()` on the success path is load-bearing, not tidiness. Measured on
the same Node: a worker that replies correctly and *then* starves keeps the
whole process alive indefinitely — the parent got its verdict and still had to
be killed after 6s. Terminating a fully starved thread resolved in 6–15ms in
both the microtask and the async-recursion case, and the parent exited clean.

One Worker per `evaluate()` call, spawned and terminated inside that call; no
pooling, no reuse, no request-id correlation. A portcall run does one or two
PAC evaluations, and per-call spawn mirrors ADR-0011's own fresh-context-per-
call discipline.

## Alternatives considered

- **Keep `vm`'s `timeout` and add a microtask-shaped guard inside the
  sandbox** — freeze `Promise`, strip `async` support, pattern-match the
  script. Rejected: it is a blocklist against a language feature set, and the
  measurement above is two shapes found in an afternoon, not an exhaustive
  list. ADR-0011's items each close a nameable attack; a guess at the next
  starvation shape would not.
- **A child process instead of a thread.** Rejected for the same boring
  reason ADR-0011 gave for the whole idea: this runs on a customer's laptop
  under an unknown runtime, and process spawn plus IPC plus a second Node
  bootstrap costs materially more per call than a thread that shares the
  already-loaded runtime. `terminate()` gives the same "kill it from
  outside" property the process boundary was wanted for.
- **Accept the hang and document it.** Rejected: a hung run produces no
  report and no exit code, which is worse than any wrong finding — the
  deterministic-exit-code contract (ADR-0006) stops being true if a PAC
  script can stop the process from reaching it.

## Consequences

The proxy probe's PAC path is now asynchronous where it was synchronous, and
carries a thread spawn per evaluation — accepted, at one or two per run.
`pac-worker.ts` must exist as a real module next to its emitted sibling in
`dist/`, so `pac-sandbox.ts` derives the sibling's extension from
`import.meta.url` rather than hard-coding one.

This record supersedes, in part, ADR-0011's rejection of process/worker
isolation as an alternative: that rejection assumed the six in-process
measures already bounded CPU exhaustion, and the measurement above shows item
4 does not. The six measures themselves stand unchanged, and ADR-0011 remains
Accepted for everything else it records.
