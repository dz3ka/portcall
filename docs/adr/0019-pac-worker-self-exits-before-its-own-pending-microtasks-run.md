# ADR-0019: The PAC worker self-exits before its own pending microtasks run

- **Status:** Accepted
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

ADR-0018 closed confinement — a PAC script that answers cannot have touched
anything outside its realm to produce that answer. Gadget 7 is a different
kind of gap, found after ADR-0018 landed: a script that answers cleanly and
*then* keeps running.

`test/fixtures/pac/hostile-escape-async-continuation.js`'s `FindProxyForURL`
returns `"DIRECT"` synchronously, same as any well-behaved script. The attack
is a `.catch` handler attached to a dangling `import("node:fs")`, which
`refuseDynamicImport` (ADR-0018, item 4) does correctly refuse — but the
rejection it produces is an ordinary object of the sandbox's own realm, and
`e.constructor.constructor("return process")()` reaches that realm's live
`Function` the same way gadget 2 did. The difference is timing: this `.catch`
continuation is a microtask, and it does not run until the synchronous call
that produced `FindProxyForURL`'s return value yields control back to the
event loop. `pac.ts`'s `evaluatePac` returns before that turn ever happens —
but `pac-worker.ts`, the Worker-thread entry point wrapping that call
(ADR-0017), does nothing to stop its own event loop from taking that turn
afterward. The worker had already sent its verdict via `postMessage`; the
rejection ran anyway, one tick later, on a thread nothing was watching
anymore.

This is a liveness/ordering gap, not a confinement gap: ADR-0018's boundary
held (the script never gained access to anything it wasn't going to reach
anyway once `codeGeneration` and the realm design permit that `Function`
lookup); what was missing was a promise that no code runs *after* the
worker's job is already reported done.

## Decision

`pac-worker.ts:55` calls `process.exit(0)` immediately after `postMessage`,
in the same synchronous tick, with nothing async in between:

```ts
parentPort?.postMessage(response);
process.exit(0);
```

This is a worker-level invariant: `pac-worker.ts` self-exits before its own
event loop would ever get a turn to run the pending rejection microtask. It
is stated here as its own claim because a second, similarly-shaped claim
exists at a different layer, and the two are not the same guarantee:

- **Worker-level** — "`pac-worker.ts` self-exits before its own event loop
  would run the pending rejection." This is what this ADR and WP14a actually
  implement. It is proven by a test that talks to `pac-worker.ts` directly:
  `test/proxy-pac-escape.test.ts`'s `"gadget 7's worker-level invariant
  (ADR-0019)"` describe block constructs a raw `new Worker(new
  URL('../src/probes/proxy/pac-worker.ts', import.meta.url))`, bypassing
  `createPacSandbox()` entirely, posts it the async-continuation fixture, and
  awaits with no `terminate()` in the race — so nothing but `process.exit(0)`
  can be the reason the canary never appears.
- **Seam-level** — "no canary escapes through `createPacSandbox()`." This is
  real, and true today, but it is *not* guaranteed by `process.exit(0)`: it
  is guaranteed by `pac-sandbox.ts:88`, whose `finish()` calls
  `worker.terminate()` synchronously inside the `'message'` handler, before
  `resolve()` runs. That `terminate()` call kills the worker's thread outright
  and, measured against the gadget-7 fixture with `process.exit(0)` removed
  (20 trials via a worker wired through the real `createPacSandbox()`), won
  the race in 17 of 20 runs — a real but non-deterministic mitigation, not a
  guarantee independent of `process.exit(0)`. It is a second layer at the
  caller side, added for a different reason (ADR-0017's watchdog) and never
  designed against this gadget, so it happens to narrow the window most of
  the time without closing it.

The root cause of needing two separate tests, not one, is exactly that
independence. The existing seam-level test
(`test/proxy-pac-escape.test.ts`, `'gadget 7: a rejection handler reached
after the reply cannot write outside the working directory'`) goes through
`createPacSandbox()`, so `pac-sandbox.ts:88`'s `terminate()` already makes it
pass most of the time — but per the 20-trial measurement above, it would be
expected to flake, not fail cleanly, with `process.exit(0)` reverted: 3 of
20 runs still leaked the canary. A test whose pass/fail is a race outcome
rather than a direct assertion on the fix under test is not a regression
test for that fix; its comment has been rewritten as a MEASURED CAVEAT saying
so plainly (idiom from `test/fixtures/pac/hostile-escape-dynamic-import.js:9-21`).
The worker-level test above is the one that actually fails without
`process.exit(0)`, because it removes `terminate()` from the race entirely.

Seam-level truth is still worth having on record: it means today's production
path (`src/probes/proxy/index.ts` → `createPacSandbox()`) is not exposed to
gadget 7 even by the caller's own timing accident, independent of this ADR's
fix. But it means `process.exit(0)` is not the *only* thing standing between
the current production seam and a leak — `terminate()` is doing that job at
the seam today. What `process.exit(0)` is the only thing standing behind is
any caller that does not `terminate()`: a future timing change to
`pac-sandbox.ts`'s `finish()`, or any other caller that talks to
`pac-worker.ts` directly (as the worker-level test now does, deliberately, to
prove exactly this).

## Alternatives considered

- **Test-only delay in `pac-sandbox.ts`'s `terminate()` path.** Rejected: it
  shapes production code around a test's convenience, and it is the wrong
  target regardless — a delayed `terminate()` still eventually wins the race
  against the same microtask, so it would still be testing the seam's
  `terminate()` timing, not `pac-worker.ts`'s own invariant. Handicapping the
  wrong mechanism is not the same as isolating the right one.
- **Synchronous busy-work in the fixture to shift the race earlier.** Rejected:
  this still races `terminate()`, not `process.exit(0)`; it is exactly as
  fragile as the seam-level test already proved to be, and it does not
  isolate which of the two mechanisms is doing the work.
- **Spy or mock `process.exit` and assert it was called synchronously.**
  Considered and rejected on measurement: `pac-worker.ts` runs inside a real
  `worker_threads` `Worker`, with its own `process` binding on its own thread.
  A `vi.spyOn(process, 'exit')` set up in the main test thread has no way to
  reach the worker thread's `process` object — there is no shared reference
  to intercept. Making this work would need a preload or monkeypatch script
  injected into the worker itself, which is more new moving parts, for a
  purely structural assertion, than the test actually chosen (which asserts
  the *outcome* — no canary file — directly).
- **Document the seam-level race as a caveat only, with no new test.**
  Rejected: this is exactly the trap the seam-level test's original comment
  was in before this session — a caveat describes a gap honestly but proves
  nothing. A regression test's job is to fail without the fix; a comment
  cannot fail. This is the strongest argument for why a second, worker-level
  test was needed rather than just a better-worded comment on the first one:
  without it, nothing in the suite would have caught `process.exit(0)` being
  reverted.

## Consequences

ADR-0018 stands unchanged for confinement; this ADR closes a liveness/timing
gap in the worker seam, one turn of the event loop later than anything
ADR-0018 examined. Neither implies the other: gadget 7's dangling rejection
ran inside a realm ADR-0018 had already confined correctly, and ADR-0018's
repros never depended on what happens after the worker's message handler
returns.

Both escape repros — the seam-level test (defense-in-depth, currently passing
because of `pac-sandbox.ts:88`'s `terminate()`, honestly captioned as such)
and the worker-level test (the actual regression test for this fix) — stay in
`test/proxy-pac-escape.test.ts` as permanent regression coverage. Removing
`process.exit(0)` from `pac-worker.ts`, or moving it behind any `.then`,
`await`, or `setImmediate`, reopens gadget 7 at the worker level even if
`pac-sandbox.ts`'s `terminate()` timing happens to still mask it at the seam
— which is exactly why the worker-level test talks to `pac-worker.ts`
directly and never calls `terminate()` itself.
