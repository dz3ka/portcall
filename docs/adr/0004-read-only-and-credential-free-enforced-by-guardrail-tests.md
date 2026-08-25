# ADR-0004: Read-only and credential-free, enforced by guardrail tests

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §4 states four hard properties: no writes outside the working directory,
no credential access, no telemetry, and no network calls to hosts the active
profile does not name. They are the product. A security team that cannot satisfy
itself in ten minutes that running this is safe will not run it, and then
nothing else in the repo matters.

A README paragraph is worth close to nothing here, because the reader has been
told things before. Worse, all four properties are trivially true on the first
day and easy to lose later — not through malice, but through a plausible probe.
"Just check whether the OS already trusts this root" is one `security find-
certificate` away from reading a keychain; "cache the resolved chain" is one
`writeFile` away from a write in `$HOME`. The failure is silent and it happens
in a diff that looks reasonable.

## Decision

Each property is a test in `test/guardrails/`, running on every `npm run verify`:

- `no-writes.test.ts` runs the CLI as a child process with `HOME`/`USERPROFILE`
  and the OS temp directory redirected into a sandbox, takes a full file
  inventory before and after, and fails on any new or modified file outside the
  run's own `cwd`.
- `no-credential-access.test.ts` scans `src/` for keychain, `.ssh`, browser
  profile and interactive-prompt patterns, with one documented allowlist entry:
  `cli/help.ts`, which is *required* to say those words in its disclosure text.
- `no-telemetry.test.ts` scans for known analytics hosts and for a module-scope
  outbound call — one that would fire merely on import.
- `no-network-outside-allowlist.test.ts` holds the rule that only `src/net/` may
  import a networking API. `NetworkGuard` (`src/net/guard.ts`) is built from the
  active profile, is the only thing that opens a socket, and admits a
  runtime-discovered host (a proxy, a PAC server) only through `permit()` with a
  stated reason, so the report can disclose every host contacted and why.

These were written before the first probe, so no probe has ever run without
them. They are run by `npm run verify` locally and by the `verify` job in
`.github/workflows/ci.yml`, which runs that same command on ubuntu, macos and
windows, so a violation that only shows on one of the three still goes red.

## Alternatives considered

- **Document the properties and rely on code review.** Rejected: it is the
  status quo of every tool the customer's security team has already been burned
  by, and it degrades quietly — nobody notices the review that did not happen.
- **A real filesystem watcher (fanotify / FSEvents / ReadDirectoryChangesW).**
  Rejected for now, and it is strictly the stronger check. There is no portable
  one across the three runners this project must be green on, and a check that
  runs on one OS would give false confidence about the other two. The inventory
  diff is the honest substitute and says so in the test's own comment.
- **Sandbox the process at run time (seccomp, a permission flag).** Rejected for
  the boring reason: this runs on a customer's laptop under whatever runtime and
  invocation they choose. We do not control the launch, and a property that
  depends on the operator passing a flag is not a property.
- **Per-probe self-restraint — each probe promises to behave.** Rejected: that
  is a per-call-site rule, the same shape ADR-0005 rejects for redaction and for
  the same reason. Rules with no mechanism behind them decay at the twentieth
  call site.
- **Only test the properties, without the `NetworkGuard` type.** Rejected: a
  scan tells you a rule was broken after someone broke it. The guard makes the
  allowed set explicit at run time and gives the report something true to say
  about what was contacted.

## Consequences

Three of the four checks are static text scans, and a static scan cannot prove
absence — a determined obfuscation walks past all of them. They are trip-wires
against the obvious mistake, they say that in their own comments, and the
project does not claim more.

The allowlist has one entry and a paragraph explaining it. Keeping that
documented in the test rather than broadening the pattern is the discipline that
keeps the guardrail meaningful.

A future probe that legitimately needs a new capability now has to argue with a
test. That is intended. When a check cannot be done without breaking one of
these properties, the check is out of scope (CLAUDE.md) and the ADR to write is
the one that says so — not a quiet edit to the allowlist.
