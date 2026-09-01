# ADR-0040: The trust-store reader hands PowerShell a null module-analysis cache path

- **Status:** Accepted — does **not** supersede ADR-0039; that record's
  `60_000` ceiling and its whole argument stand untouched
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

`verify (windows-latest)` went red at `f4ff635` (run `33477267513`):
`test/guardrails/no-writes.test.ts`, two tests failed against 850 passing, on
one line of diff — `+ "new file: AppData/Local/Microsoft/Windows/PowerShell/ModuleAnalysisCache"`.

The trust-store reader shells out to Windows PowerShell 5.1 to enumerate
`Cert:\LocalMachine\Root`. PowerShell caches its module analysis in a binary
blob under the user profile, and the guardrail that snapshots the sandboxed
home before and after a CLI run saw the file appear. The guardrail is correct:
portcall started the process, so the process's writes are portcall's, and
SPEC.md §4's first non-negotiable says there are none outside the working
directory.

Four things were measured on a real Windows 11 host, single-variable spawns of
the pinned command. They are what this decision rests on.

**1. The `5_000` → `60_000` ceiling is what let the write land.** With
`PSModuleAnalysisCachePath` pointed at a scratch directory, a 5 s child
lifetime produced **no file**; a 25 s lifetime produced a **9 426-byte
`ModuleAnalysisCache`**. Exit 0 and 60 406 stdout bytes both times. The flush is
deferred, and under the old row ceiling the `SIGKILL` arrived first. So this is
not a regression ADR-0039 caused; it is a write that was always being attempted
and was previously being killed mid-flight. Lowering the ceiling again would
re-hide it, not prevent it, and would re-break the Windows read ADR-0039 exists
to fix.

**2. `PSModuleAnalysisCachePath=NUL` suppresses the file entirely**, and
Windows PowerShell 5.1 honours it on that host: a 25 s tail wrote nothing
anywhere in the sandbox tree, left the real profile cache untouched, exited 0
and returned the full output. `\\.\NUL` behaves identically; plain `NUL` is the
spelling Microsoft documents.

**3. Dropping `LOCALAPPDATA`/`APPDATA` from the passthrough cannot fix it.**
That was the obvious first guess and it is disproven from both sides.
`test/guardrails/no-writes.test.ts:112-121` hands the CLI an environment with
**neither name set**, so `minimalEnv()` forwarded neither — and the CI runner
still wrote the cache under `<home>/AppData/…`. From the other side: with
`LOCALAPPDATA` pointed at a scratch directory, PowerShell wrote nothing there.
PowerShell 5.1 resolves that folder from the *profile* (via `USERPROFILE`), not
from `$env:LOCALAPPDATA`. The environment variable does not control the
location; `PSModuleAnalysisCachePath` does.

**4. The guardrail under-detects; it does not over-fire.** On the developer
laptop the same run resolves the cache to the real `%LOCALAPPDATA%`, which the
guardrail's sandbox snapshot never covers. The write happens locally too — it
is simply invisible, which is the entire reason local `verify` is green and CI
is not. Any argument that starts "the guardrail's scope is too wide" has the
sign backwards.

## Decision

**`minimalEnv()` sets one fixed literal on win32:
`env.PSModuleAnalysisCachePath = 'NUL'`.** The cache is **suppressed, not
relocated**. The function's signature is unchanged; every other platform still
gets `{}`; the win32 branch is now the eight existing passthrough names plus
this one fixed value.

Fixed, and never a passthrough, is the load-bearing half. Everything else in
that function copies a value the calling environment chose. This one may not:
whatever a customer has set for `PSModuleAnalysisCachePath` is a *place to
write*, and the point of the decision is that there is no place to write.

The pinned command table does not move — not the argv, not `timeoutMs`. This is
an environment change, and the child's environment is already asserted
behaviourally, through a real spawn, in `test/net-os-truststore.test.ts`'s
`os trust store reader child environment` block; that is where the new test
goes.

## Alternatives considered

- **Relocate the cache into the working directory.** The only file portcall may
  create in a customer's working directory is the `--out` report the operator
  asked for by name. A binary cache blob nobody requested, with no deletion
  path, satisfies the letter of "no writes outside the working directory" while
  breaking the point of it — and a working directory that is read-only is a
  perfectly ordinary thing to be run in.
- **Relocate the cache into `%TEMP%`.** The guardrail snapshots the sandboxed
  temp as well as the sandboxed home, so this fails in exactly the same way. It
  is not even a relocation from the guardrail's point of view; it is the same
  failure with a different path in the message.
- **Drop `LOCALAPPDATA`/`APPDATA` from the passthrough.** Disproven by finding
  3 — the CI failure occurred with both already absent from the child's
  environment. It also re-buys the startup penalty the scratch-location
  amendment removed, in exchange for nothing.
- **Suppress via the invocation rather than the environment** (a `-Command`
  prologue, or a different argv). This moves a pinned row that
  `test/guardrails/subprocess-boundary.test.ts` exists to hold still, needs a
  new fixture, and has zero measurement behind it. The environment variable has
  a measurement (finding 2).
- **Argue the guardrail's scope is wrong and narrow it.** Rejected on finding
  4: it under-detects rather than over-fires, so the honest correction runs the
  other way. Weakening a guardrail to make a red build green is also precisely
  what ADR-0025 forbids.
- **Change nothing in `src/`; widen the no-writes sandbox and book the cache as
  a third-party write.** Fails the first non-negotiable as written — portcall
  started the process, so the write is portcall's — and it leaves the same file
  landing in a real customer's profile, which is the case the rule exists for.
  A rule that only binds when the writer is our own code is not the rule
  SPEC.md §4 states.

## Consequences

- **Every spawn now pays a cold module-analysis cache, measured at ≈ +140 ms.**
  Time to first byte, n=4 per arm, one host, one variable moved: warm readable
  cache **156–189 ms**, `NUL` **306–310 ms**, cold-but-writable cache path
  **293–371 ms**. `NUL` costs what a cold cache costs, to the millisecond band —
  the penalty is "cache not read", and it is not a new class of cost. The first
  spawn on a cold CI runner already paid it before this change; what is gone is
  the saving on the second and later spawns, of which a portcall run has one per
  store.
- **That cost is unmeasured on `windows-latest`, and it does not matter at this
  ceiling.** Even at ten times the laptop figure (≈ 1.4 s) it sits far inside
  the ~17 s of headroom `60_000` holds over the one cold read measured to
  completion, 42 859 ms.
- **The `minimalEnv()` doc-block's rationale had to change with it**
  (`src/net/os-truststore.ts:170`, and the same claim in the file header at
  `:48`). It justified forwarding `LOCALAPPDATA`/`APPDATA` as giving PowerShell
  "a place to keep its `ModuleAnalysisCache`". With the cache suppressed the
  cache is kept nowhere, so that sentence became false the moment the literal
  landed. It now says plainly that those names are **retained on an unmeasured
  possibility**, not on the cache rationale. The sibling test's title and
  comment were corrected the same way; what it asserts is unchanged.
- **This does not supersede ADR-0039.** Nothing here is an argument about the
  ceiling. The relationship is only that the higher ceiling is what stopped
  hiding this write.
- **Open question, deliberately left open: are `LOCALAPPDATA` and `APPDATA`
  still buying anything?** They were added for a cache that no longer exists,
  and no measurement says whether they matter without it. They are retained on
  purpose — a commit whose job is to unbreak CI is the wrong place to make a
  second, unmeasured change to the child's environment on the governing host.
  Whether to A/B them on `windows-latest` and drop them if they are free is
  unanswered, and should be answered by measurement rather than by reading this
  ADR as permission either way.
- **What the new test proves, and what it does not.** It asserts through a real
  spawn that the child sees `PSModuleAnalysisCachePath=NUL`; that is a claim
  local `verify` can check on any Windows host. That no file then appears rests
  on finding 2 and on `no-writes` running on `windows-latest` — by finding 4,
  the local guardrail cannot see this write at all, so CI remains the only
  witness for the second half.
