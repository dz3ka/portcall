# ADR-0011: PAC sandbox hardening, one item per distinct attack

- **Status:** Superseded by
  [ADR-0018](0018-pac-confinement-is-a-fresh-realm-not-a-hardened-host-object.md)
  — item 5's freeze rationale and this record's "CPU, not filesystem or
  network" claim were disproved by a working sandbox escape. Item 4 and one
  rejected alternative had already been partly superseded by
  [ADR-0017](0017-pac-evaluation-runs-on-a-terminable-worker-thread.md). The
  text below is left exactly as it was written, wrong sentences included;
  ADR-0018 names which of the six measures still stand.
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

ADR-0010 picks `node:vm` as the execution engine for PAC scripts, but `vm`
isolates the global object and scope chain — it is not, by itself, a security
boundary against a hostile script. Node's own docs are explicit that `vm` does
not protect against denial-of-service or malicious code that finds a way to
reach objects outside the sandbox. A PAC script here is attacker-influenceable
content by construction (a WPAD server on the local network, or a
`proxy.pac_url` naming a host this run does not otherwise control), so running
it at all needs a stated, reviewable set of defences rather than a bare
`vm.runInNewContext` call.

## Decision

`evaluatePac` (`src/probes/proxy/pac.ts`) applies six independent measures.
Each is reviewed and kept because it defends a distinct attack a PAC script
could otherwise mount; none is redundant with another:

1. **Size cap before compilation** (`MAX_SCRIPT_BYTES`, 1 MB) — rejects an
   oversized script before `node:vm` ever sees it, so a multi-hundred-MB PAC
   response cannot spend compile time or memory regardless of what the
   sandbox itself would allow.
2. **Fresh `vm.createContext` per call, no state reuse** — a hostile script
   cannot leave state (a mutated global, a planted timer) that a later call
   for a different host or a later run inherits.
3. **`codeGeneration: { strings: false, wasm: false }`** — blocks `eval`,
   `new Function(...)`, and WebAssembly compilation from inside the script,
   the standard escape route from "the sandbox only restricts my starting
   scope" to "I can compile and run arbitrary new code".
4. **`script.runInContext(context, { timeout: timeoutMs })`** — kills
   `while(true){}` and similar. The script's top-level code and the
   `FindProxyForURL` call are compiled and run as one combined script, so the
   timeout bounds a loop hidden inside the function body too, not just the
   script's top level. *(Partly superseded by ADR-0017: `timeout` bounds
   synchronous execution only, and does not observe a microtask or
   async-recursion loop at all. It is kept for the synchronous case; the
   asynchronous case is bounded by the Worker watchdog ADR-0017 adds.)*
5. **A minimal, frozen-function global** — the sandbox exposes only the eight
   PAC helper functions (`dnsResolve`, `isInNet`, `myIpAddress`, etc.) plus
   two plain-value handoff slots; no `require`, `process`, `global`, or
   `Buffer`. `vm.createContext` does not add Node's own globals unless the
   sandbox object supplies them, and this one deliberately does not. Each
   helper function is `Object.freeze`d as belt-and-suspenders against a
   prototype-chain gadget reaching `Function`, on top of `codeGeneration`
   already blocking that chain from compiling anything.
6. **The helper functions themselves never resolve arbitrary names** — see
   ADR-0012, which is this same hardening effort applied to the one class of
   helper (`dnsResolve`/`isInNet`/`isResolvable`) that could otherwise turn
   the sandbox into a side-channel reaching outside it.

This was a razor-reviewed list during the M2 design pass: nothing on it was
found cuttable, because removing any one item reopens a specific, nameable
attack the others do not cover.

## Alternatives considered

- **Trust `vm`'s context isolation alone, skip the extra measures.**
  Rejected: Node's own documentation says `vm` is not a security mechanism by
  itself, and this project's non-negotiables (CLAUDE.md — no writes, no
  network outside the allowlist, no credential access) are exactly the
  properties an unbounded script execution could violate if any one of the
  six items above were missing.
- **Run the PAC evaluation in a child process instead of `vm`.** *(This
  rejection is superseded by ADR-0017, which moves the evaluation onto a
  terminable Worker thread — the reasoning below assumed item 4 bounded CPU
  exhaustion, and measurement showed it does not.)* Rejected:
  it trades one class of problem for the operational cost of process
  spawning and IPC on a customer's laptop under an unknown runtime
  environment (SPEC.md's "runs on a customer's machine" constraint), for
  protection this project's six in-process measures already provide against
  the concrete attack surface a PAC script has (CPU, not filesystem or
  network — see the sandbox's frozen global).
- **A configurable/looser timeout.** Rejected: legitimate PAC scripts run in
  well under a millisecond (`PAC_EVAL_TIMEOUT_MS` is 1000ms, generous
  headroom), and a slower legitimate script is not a case this tool needs to
  accommodate — it is evidence the script is doing something unusual, which
  `error` already reports honestly.

## Consequences

A PAC script that legitimately needs `eval`/`Function` (none observed in the
wild; PAC is meant to be declarative routing logic) reports `error` rather
than a verdict — accepted, because the alternative is a compile-time escape
hatch for every hostile script too.

The hardening list is now a load-bearing part of the security story this repo
tells a reviewer. Removing an item requires a superseding ADR naming which
attack it reopens, not a quiet deletion during a later refactor.
