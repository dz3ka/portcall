# ADR-0018: PAC confinement is a fresh realm, not a hardened host object

- **Status:** Accepted — supersedes
  [ADR-0011](0011-pac-sandbox-hardening-defends-a-distinct-attack-per-item.md)
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

ADR-0011 lists six hardening measures and calls the list razor-reviewed. It
was reviewed, believed and acted on — and wrong about the property that
matters most. A repro driven through the *production* seam
(`createPacSandbox()`, so ADR-0017's worker and `evaluatePac` unchanged) broke
out of `node:vm` by two independent routes:

1. **The helpers were host-realm functions.** `src/probes/proxy/pac.ts`
   (155-164) put the eight PAC helpers on the sandbox as functions created in
   *this* realm, so `dnsResolve.constructor` is the host realm's `Function`
   and `dnsResolve.constructor("return process")()` hands the script the live
   `process`. The repro read `process.env` back out through the returned
   verdict and wrote a file to disk via `process.report.writeReport(...)`.
   `codeGeneration: { strings: false }` is per-V8-context; it does not
   constrain a `Function` belonging to *another* context, reached through a
   host object's prototype chain. `Object.freeze` freezes the function object
   — it does not remove an inherited `.constructor`.
2. **The contextified global was itself a host object.** With every helper
   deleted, `this.constructor.constructor("return process")()` still escaped:
   `vm.createContext(sandbox)` builds no new global, it puts an interceptor in
   front of a host object whose prototype chain still ends at the host realm's
   `Object.prototype`, and thus at the host `Function`.

The delivery path is the ordinary one. Any LAN host answering `wpad` in DNS
serves a plaintext, unauthenticated `http://wpad/wpad.dat`, which
`src/probes/proxy/index.ts` fetches and executes. That is remote code
execution on the laptop of the engineer running the audit tool, and it breaks
three of SPEC.md §4's non-negotiables at once — read-only, no credential
reads, no network outside the profile allowlist.

## Decision

Confinement stops being patches on a host object and becomes a property of the
boundary. Four changes, in `pac.ts`:

1. **The context is a real realm.**
   `vm.createContext(vm.constants.DONT_CONTEXTIFY, opts)` gives a context
   whose global is an ordinary global of the *new* realm — no host object
   behind an interceptor, so no chain out of the sandbox to walk. Closes
   gadget 2 at its root.
2. **The helpers are in-context source.** They move into a
   `PAC_BOOTSTRAP_SOURCE` constant, compiled as a bootstrap `vm.Script` run
   before the untrusted script. Each is then a function *of the sandbox
   realm*, whose `.constructor` is that realm's `Function` — which
   `codeGeneration: { strings: false }` genuinely does constrain. No host-realm
   function object is reachable at all. Closes gadget 1.
3. **Only primitives cross, both directions.** Four *string* slots seeded on
   the global and `delete`d by the bootstrap once read; the resolved target
   crosses as JSON and is `JSON.parse`d in-context; the verdict returns as the
   `runInContext` completion value, gated `typeof r === 'string'` on both
   sides. No object identity crosses either way, so a handoff added later
   cannot quietly reintroduce a gadget of this shape.
4. **Dynamic import is refused explicitly**, by a throwing
   `importModuleDynamically` hook. Without it `import("node:fs")` raises
   `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING` from a *microtask*, outside the
   `runInContext` call where no caller can catch it, killing the process — a
   liveness bug in confinement-bug clothing, fixed here because this is where
   the context options live.

**What of ADR-0011 stands.** Items 1 (size cap), 2 (fresh context per call),
3 (`codeGeneration`) and 6 (helpers never resolve arbitrary names — ADR-0012)
are unchanged and still load-bearing; item 3 is only now doing the job
ADR-0011 claimed for it, since every `Function` a script can reach belongs to
the context it restricts. Item 4 stands as
[ADR-0017](0017-pac-evaluation-runs-on-a-terminable-worker-thread.md) already
amended it — `timeout` for the synchronous case, the Worker watchdog for the
asynchronous one. Item 5's *minimal* global (no `require`, `process`,
`global`, `Buffer`) was right and survives; its freeze rationale did not.

**The two wrong claims**, both left visible in ADR-0011: item 5's
"`Object.freeze` … belt-and-suspenders … on top of `codeGeneration` already
blocking that chain from compiling anything" — gadget 1 is that chain, and it
compiled; and the child-process rejection's "the concrete attack surface a PAC
script has (CPU, not filesystem or network — see the sandbox's frozen
global)" — the repro reached the filesystem and the environment both.

ADR-0010, ADR-0012 and ADR-0017 are untouched and reaffirmed. One distinction
a reader will otherwise merge: **ADR-0017 bounds liveness** — a script that
never gives the thread back has it taken away. **This ADR bounds
confinement** — a script that does answer cannot have touched anything outside
its realm to produce the answer. Neither implies the other: the escape above
ran inside ADR-0017's worker, finished promptly, and returned a well-formed
verdict.

## Alternatives considered

- **`isolated-vm`.** Rejected: a native addon needing a compile step, which
  breaks the single-binary build (`scripts/build-binaries.mjs`) and CLAUDE.md's
  no-installs rule, and would force superseding ADR-0010 as well — to buy a
  boundary measures 1-3 already give for this threat model. A heavier
  primitive earns its cost against an adversary with time and a V8 bug; the
  property needed here is "no reference to a host object exists".
- **`vm2`.** Rejected: unmaintained, and formally abandoned by its own author
  *because of this exact escape class*. Adopting a package whose maintainer
  withdrew it over the vulnerability being fixed here would be an unusually
  direct way to reintroduce it.
- **Helpers as in-context source, keeping `vm.createContext({})`.** Rejected
  on measurement, not principle: it closes gadget 1 and leaves gadget 2 open —
  `this.constructor.constructor` still escaped with every helper removed.
  That measurement is why change 1 is not optional.
- **`Object.create(null)` as the sandbox object.** Also measured to close both
  gadgets, and recorded here as the fallback if `DONT_CONTEXTIFY` regresses.
  Rejected as the primary: it patches one prototype edge of the interceptor
  design rather than removing the host object, so it holds only while no other
  route from interceptor to host-realm object exists. `DONT_CONTEXTIFY`
  removes the question instead of answering it.

## Consequences

`DONT_CONTEXTIFY` requires Node ≥ 22.8. `engines.node` is already `>=22.18.0`
and the released binaries pin their own runtime, so no supported configuration
loses PAC evaluation — but that floor is now load-bearing and cannot be
lowered without reopening gadget 2.

The helpers are a source string rather than TypeScript now: they lose
compile-time checking, and ADR-0012's rule lives inside that string with its
fixture tests as the only guard. A real cost, accepted because the alternative
is a host-realm function object on the global, which is the bug. Stack traces
from the bootstrap name a synthetic file, not a path in the repo.

Both escape repros stay as regression tests against the production seam. They
are what this record is really about: ADR-0011's list was argued rather than
measured, and the two items it argued hardest for are the two that failed.
Removing `DONT_CONTEXTIFY`, or moving a helper back onto the sandbox object,
needs a superseding ADR naming which gadget it reopens. ADR-0011 itself is
marked Superseded and otherwise unedited, disproved sentences included —
rewriting it quietly would delete the most instructive thing in the M2 record.

The repro fixtures behind both escapes (item 1, item 2 above) live at `test/fixtures/pac/hostile-escape-helper-constructor.js` and `test/fixtures/pac/hostile-escape-this-constructor.js` (plus `hostile-escape-global-proto.js` for the generalised prototype-chain walk).
