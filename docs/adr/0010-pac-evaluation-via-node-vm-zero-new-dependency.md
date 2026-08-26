# ADR-0010: PAC evaluation via `node:vm`, zero new dependency

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §7 asks the `proxy` probe to evaluate a PAC (Proxy Auto-Config) script
against each profile endpoint — the script names a `FindProxyForURL(url, host)`
function that answers `DIRECT` or `PROXY host:port` — because on a network that
routes everything through a PAC-selected proxy, the profile's endpoints cannot
be judged reachable or not without running the same logic the browser would.

The script is real JavaScript, and it is untrusted: it comes from a WPAD server
or a `proxy.pac_url` this run does not control, and a hostile or merely buggy
one should not be able to hang the run, read the filesystem, open a socket of
its own, or exfiltrate anything through the result it returns. Whatever
evaluates it has to be a JS engine, not a partial reimplementation, because a
handful of production PAC scripts use real control flow — loops building
IP-range tables, helper functions calling each other — that a pattern-matcher
would silently misjudge.

## Decision

`FindProxyForURL` runs inside `node:vm` (`src/probes/proxy/pac.ts`), a runtime
builtin, not an npm dependency. `evaluatePac(url, host, ctx, timeoutMs)`
compiles the script text plus a call to `FindProxyForURL` as one
`vm.Script`, runs it in a fresh `vm.createContext`, and returns a closed
`PacVerdict` — never the script, never a caught error's message (see ADR-0012
for why the sandbox's helper functions are also part of this decision, and the
consequences section below).

Per this repo's norm (ADR-0002), a new dependency earns its own ADR when it
lands; `node:vm` needs none, because it is not a dependency at all — it ships
with the runtime this project already targets.

## Alternatives considered

- **An npm PAC-JS interpreter package.** Rejected: no small, actively
  maintained one exists that would not itself become the security-review
  line item this whole probe exists to avoid creating. Evaluating untrusted
  script is exactly the kind of code a security team reading this repo will
  scrutinise, and a third-party dependency for it adds a supply-chain surface
  with no corresponding gain — `node:vm` gives the same execution primitive
  with a smaller trust boundary (the Node runtime itself, already trusted to
  run this tool at all).
- **A hand-rolled JS-subset parser/interpreter.** Rejected: PAC scripts in the
  wild use real control flow, not a fixed subset, so a hand-rolled interpreter
  either grows toward re-implementing a JS engine or silently mis-evaluates
  scripts that use a construct it does not model — and it is new code in
  exactly the place correctness matters least to get wrong, since a
  mis-evaluated PAC verdict produces a wrong finding about reachability with
  no error to signal it.
- **Skip PAC evaluation, report only the WPAD/`pac_url` fetch outcome.**
  Rejected: it discards the actual question SPEC.md §7 asks — which endpoints
  route through a proxy — and leaves the operator to hand-evaluate a script
  they cannot easily test against portcall's own endpoint list.

## Consequences

`node:vm` isolates from the surrounding JS heap and global scope but is not a
full OS-level sandbox — it does not stop CPU or memory exhaustion by itself,
which is why ADR-0011 exists as a separate record: `node:vm` is necessary but
not sufficient, and the hardening measures there are what make running
untrusted script here defensible.

Re-open if a PAC script needs a JS feature `node:vm`'s `codeGeneration`
restrictions block for legitimate reasons (see ADR-0011) — the fallback there
is loosening one specific restriction with its own ADR, not adding a
dependency.
