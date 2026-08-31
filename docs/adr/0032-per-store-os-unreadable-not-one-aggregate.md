# ADR-0032: An unreadable OS store gets its own finding, not a shared aggregate

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** Bogdan Dzekic

## Context

`evaluate.ts`'s `osFindings` loop read every store in `input.osStores` and, for
anything short of a clean read, funnelled the result through a suppression
gate keyed on `osEvidenceLevel`: `explainedElsewhere` and an
`level === 'none'` / `failed.length > 0` condition decided whether a failed
store got a finding at all, and when one did fire it covered every failure
class — permission denied, the listing tool missing, an oversize store, an
empty one — under one title and one remediation string.

That gate hid two concrete, reachable gaps. The first was already in review:
on darwin, a timeout on one store plus a read failure on another produced a
timeout finding and nothing else — the second store's failure was never
named. The second the architect found while designing the fix: any run where
one store reads clean and a second store merely fails (`level === 'partial'`,
not `'none'`) never tripped the gate at all, so a genuinely broken macOS
keychain read next to a healthy one produced *no finding naming it* — silence
that read as a clean bill of health.

Both gaps trace to the same design error: the gate decided *whether to
report* based on a cross-store condition (`osEvidenceLevel`, "how many stores
altogether look bad"), when the thing worth reporting is a per-store fact —
did *this* store read.

## Decision

**Every element of `input.osStores` gets exactly one finding, chosen by that
store's own `failure` value alone. No cross-store condition gates whether the
finding fires.**

- `null` (clean read) → `truststore.os.read`
- `'timeout'` → `truststore.os.read-timeout`
- `'aborted'` → its own finding, via an explicit `continue` in the loop (see
  the aborted-branch fall-through fix below) — previously fell through into
  the same handling as a clean miss
- anything else (`reader-missing`, `reader-failed`, `output-too-large`,
  `no-certificates`) → `truststore.os.unreadable`, once, for that store

`truststore.os.unreadable` is not one finding shared across all failed
stores — one fires per store, each carrying that store's own evidence
(`store`, `store read` path, `failure`, `code`). The four failure classes
share **two** title constants ("could not be read" for the first three,
"was read and held no certificates" for `no-certificates`) but each gets its
own remediation string via `OS_READ_FAILURES`, a `Record` keyed on
`Exclude<TrustStoreFailure, 'unsupported-platform' | 'timeout' | 'aborted'>`
— TypeScript's exhaustiveness check on that key type is what proves the four
rows are the complete set, not a runtime `default` branch. The one case with
no store to hang a finding on — `osStores` is empty, nothing ran — keeps its
own aggregate, `unsupportedPlatformFinding()`, `failure: 'unsupported-platform'`.

Severity stays `unknown` for `os.unreadable`, unchanged: it still rolls up as
non-zero, so a half-read machine can never present as clean.

**This is a net-negative complexity change.** `explainedElsewhere` and the
`level === 'none'` / `failed.length > 0` gate are deleted outright, not
replaced by a narrower gate. What replaces them is a plain per-store branch
with no cross-store state to reason about.

## Alternatives considered

- **Keep the aggregate, add residual "also failed" evidence when the
  suppressor fires.** Rejected: still one failure class under one
  remediation covering two different operator tickets (a missing tool and a
  killed oversize read demand different fixes), and the residual list has no
  honest title of its own.
- **Keep the aggregate, drop only `explainedElsewhere`.** Rejected: the
  finding's evidence becomes `store/failure/code × N` with duplicate labels
  and a single remediation trying to cover four classes at once; the
  `level === 'partial'` gap survives untouched.
- **Fix only the reviewed darwin timeout+failure scenario.** Rejected: this
  is the narrower of the two gaps. It leaves the `partial`-level case — a
  failed store next to a healthy one — silently unnamed, which is the more
  common shape (most machines have more than one candidate OS store) and the
  more misleading one, since a `partial` result already looks closer to
  healthy than `none` does.

## Consequences

**A property test enforces the shape going forward:** every failed store's
`failure` kind appears in the evidence of some finding, and every non-`ok`
finding satisfies `assertRemediable` — a future failure class added to
`TrustStoreFailure` without a matching `OS_READ_FAILURES` row now fails at
the type level (the `Exclude<...>` key type) before it can fail silently at
runtime.

**The aborted-branch fix is the same bug class, caught the same way.** An
aborted read was falling through the same switch/if-chain as a clean miss
because it was one of the branches the old cross-store gate's remediation
loop did not distinguish; giving it an explicit `continue` and its own
`truststore.os.aborted` finding closes that fall-through directly rather than
as a side effect of deleting the gate.

**Nothing downstream changes shape.** `runtimeFindings` and
`missingRootFinding` read `OsCoverage` (`level`, `read`, `unread`,
`unparsed`), computed once in `crossCheck`, not the per-store findings
themselves — so widening `os.unreadable` from one aggregate to N per-store
findings changes what an operator reads, not what any other finding's logic
branches on.
