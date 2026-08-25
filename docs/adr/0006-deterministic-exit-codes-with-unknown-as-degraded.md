# ADR-0006: Deterministic exit codes, with `unknown` as degraded

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

Portcall is meant to be run twice: once by an FDE before the first call, and
then repeatedly by the customer in their own CI, as a gate on whether the tool
they bought still works from a build agent. In the second case the exit code is
the only part of the output anything reads. That makes the mapping API — change
one value and every pipeline built on it silently changes meaning (SPEC.md §9.6).

The finding model has four severities and the process has four outcomes, but
they are not the same four. `blocker`, `degraded` and `ok` describe the
customer's environment. `unknown` describes the *check*: it ran and could not
decide. And none of them describe portcall itself failing, which is a fourth
thing a pipeline needs to tell apart from the other three.

## Decision

`src/cli/exit-codes.ts` fixes the mapping:

| Code | Meaning |
|------|---------|
| `0` | `ok` — no blockers |
| `1` | `degraded` — works, with limitations |
| `2` | `blocker` — will not work here as configured |
| `3` | tool error — bad arguments, unreadable profile, internal failure |

Findings roll up worst-first and `exitCodeFor` maps the result. **`unknown` maps
to `1`, not `0`.** A check that ran and could not decide is not a pass.

`3` is reserved: it is produced only by portcall failing, never by a finding, so
"your network blocks this" and "your invocation is wrong" are never the same
signal. An empty run — M0, with no probes registered — is `ok`/`0`, deliberately
not `unknown`: nothing was checked, so nothing was indeterminate.

## Alternatives considered

- **`unknown` → `0`.** Rejected: it lets a pipeline go green on a machine where
  the tool is in fact unusable, which is the precise failure this project exists
  to prevent. A gate that passes on missing information is worse than no gate,
  because someone will trust it.
- **`unknown` → `2`.** Rejected: it is not a blocker, it is missing information.
  A tool that fails the build over what it could not determine teaches people to
  append `|| true`, and then the real blockers stop failing the build too.
- **One non-zero code for everything that is not ok.** Rejected: it collapses
  "the tool will not work here" into "portcall crashed". That is the same
  collapse CLAUDE.md forbids for DNS versus connect-refused versus timeout, for
  the same reason — different codes, different teams, different tickets.
- **A wide code space, one per probe class (10 = TLS, 11 = proxy...).**
  Rejected: exit codes are one byte and only portable across shells in the
  0–125 range, the detail already exists in the JSON report, and wide code
  spaces get partially implemented and then misremembered by whoever writes the
  pipeline.
- **Always exit `0` and put the verdict in the JSON.** Rejected for the boring
  reason: a CI job that can never fail is a CI job nobody looks at, and gating
  on it would require `jq` on a locked-down build agent — one more thing to
  request from one more team.

## Consequences

The mapping is frozen at the first public release; changing a value is a major
version, and `3` has to stay clean of finding-derived exits for the distinction
to keep working.

A customer whose environment defeats a probe — EDR blocking raw sockets, say —
gets a non-zero exit on a machine that is otherwise fine. That is the accepted
cost of the `unknown` → `1` choice, and it is the reason the remediation text on
an `unknown` finding has to be as good as the one on a blocker: it is what the
person staring at the red build will read.

Re-open only if a real customer pipeline needs "run and report but never fail".
The answer there is an explicit flag (`--exit-zero`) that says so in the output,
not a remap that makes the codes mean something different everywhere else.
