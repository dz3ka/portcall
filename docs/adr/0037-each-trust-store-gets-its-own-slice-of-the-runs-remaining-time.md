# ADR-0037: Each trust store gets its own slice of the run's remaining time

- **Status:** Accepted — retroactive write-up. The decision was made and landed
  on 2026-08-28 in `be2eca1` ("Give each trust store its own slice of the run's
  remaining time"); the record slipped past M4's docs pass, and by the time
  ADR-0039 came to argue against one of its numbers it had to note in its own
  Status line that the principle it upholds "is **not yet written up** in this
  directory". This closes that. Nothing below is new reasoning
- **Date:** 2026-09-01 (decision: 2026-08-28)
- **Deciders:** Bogdan Dzekic

## Context

The trust-store reader had a single 5 s constant that no production code path
ever reached. WP6 was about to promote it to the real budget, and that promotion
would have let one slow store eat a whole run: three `win32`/`darwin` rows read
in series, each entitled to the full ceiling, with nothing subtracting what the
earlier ones already spent.

The opposite failure is just as reachable. `truststore` is the last probe to
run, so it is reading against whatever the four probes before it left of the
run's deadline; a read that spends the final millisecond leaves the probe
nothing with which to turn its outcomes into findings, and the run dies with the
evidence in hand.

And there is a third thing tangled in the same number. A read can run out of
time for two opposite reasons — the run's clock ran out, or the store itself was
slower than a healthy read of that store should be — and those two demand
opposite actions from an operator. "Re-run with `--timeout` raised" is true in
the first case and a lie in the second, where a longer wait buys the same
answer.

## Decision

**Every row of the pinned command table carries its own healthy-read ceiling,
and the reader clamps that ceiling down — never up — against what the run
deadline actually leaves at the moment that row is read.**

- `TrustStoreCommand.timeoutMs` is **the healthy-read ceiling for that store on
  that platform**, derived from what a healthy read of *this* store costs, never
  from how long a sick environment took. A host that exceeds it gets a finding,
  not a longer wait. It is a source literal on the pinned row, and the guardrail
  pins it by value, so changing a budget is a reviewed diff rather than a quiet
  retune.
- `storeBudgetMs()` is `max(0, min(row.timeoutMs, deadline - now - reserve))`,
  recomputed **per row, inside the loop**, so a serial read sees the previous
  row's spend.
- `STORE_BUDGET_RESERVE_MS` (2 s) is held back unspent, so the probe can still
  build findings after the last store answers.
- Below `MIN_STORE_BUDGET_MS` (1 s), **no child is started at all**: report, do
  not gamble. A sub-second budget cannot read any store this table names, so
  spawning into it buys a `signal:SIGKILL` that blames the machine for the run's
  own clock. The outcome is `failure: 'timeout'`, `code: 'budget-exhausted'`.
- **Zero is the reader's word for "nothing ran".** Both no-spawn paths —
  `budget-exhausted`, and a run signal that had already fired — report
  `budgetMs: 0`, because a budget is a statement about a process and neither has
  one. A fired run signal outranks the budget branch: "the operator pressed
  Ctrl-C" is not a claim about this machine's clock.
- `budgetMs` lives on the outcome rather than as a local in the reader because it
  has **two** consumers: it is `number` evidence on the finding, *and* it is how
  the probe tells the two timeouts apart. `budgetMs` below the row's `timeoutMs`
  means the run's remaining time bound the read, so a longer `--timeout` is the
  fix; `budgetMs` equal to it means the store outran a healthy ceiling, and no
  knob portcall exposes changes that. `readTimeoutRemediation` writes both
  sentences and refuses to share one.
- The probe is handed `context.deadline`, not a timeout of its own. The per-store
  budget belongs to the row and the run belongs to the run, so there is no
  caller-supplied number for a test to drift apart from — and `truststore` must
  be registered **last** for the arithmetic to mean anything.
- The pinned table reaches the pure evaluator as data (`CrossCheckInput.
  osCommands`), for its `timeoutMs` column and nothing else; importing it would
  drag the module that starts processes into the pure half.
- **When no OS store could be read at all, no runtime verdict is emitted — not
  the bad one and, load-bearingly, not the good one.** `osEvidenceLevel` decides
  that and `truststore.crosscheck.indeterminate` says so out loud: with no store
  read the locally-added set is *undefined*, and a green finding standing on an
  undefined set is worse than no finding.

## Alternatives considered

- **One run-wide timeout shared by every store.** Rejected: three rows in series,
  each entitled to the whole ceiling, is a design in which one slow store
  consumes the run and the later stores are never read.
- **Give the caller a per-store timeout knob.** Rejected: it puts the budget in
  two places, and a caller-supplied number is one a test will pin and then drift
  away from the row. It would also make `readTimeoutRemediation`'s second arm
  dishonest — that arm is true precisely *because* portcall exposes no knob for
  the row.
- **Spawn anyway when under a second is left.** Rejected: the child is killed
  either way, but spawning produces a `signal:SIGKILL` that reads as a fault of
  the machine. Not spawning produces the honest code and costs no process.
- **Report the computed budget on the two no-spawn paths.** Rejected: it would
  print "800 ms applied" for a store no child was ever started for, and would
  cost every future consumer of `budgetMs` a standing exception. One invariant
  needs none.
- **Spend the whole remaining deadline on reads and keep no reserve.** Rejected
  for the boring reason that a probe that has read everything and cannot report
  it has done nothing.
- **One remediation string for both ways a read times out.** Rejected: it is true
  in one case and false in the other, and the operator's next action differs.
- **Raise a row's ceiling whenever a host outruns it.** Rejected as a class of
  move: that is accommodating the finding instead of reporting it. (ADR-0039 later
  re-sets `windows-machine-root` from `5_000` to `60_000` — but as a correction to
  the *sample* the ceiling was derived from, a 41-root laptop, not as a challenge
  to this rule.)
- **Keep the wall-clock assertion that a `budget-exhausted` outcome returns
  within 100 ms.** Rejected: `budget-exhausted` has exactly one producer, so "no
  child was started" is already proven structurally, and a 100 ms bound is the one
  assertion in the change that a starved CI runner could fail for no reason.

## Consequences

- The linux bundle reports `budgetMs: null`: it starts no process by design and
  has no row ceiling to be measured against, so neither a number nor zero would
  be true of it.
- `truststore` is pinned to last position in `PROBES`, and moving it breaks the
  budget arithmetic silently.
- The window between `MIN_STORE_BUDGET_MS` and true exhaustion got its own test,
  because the old suite pinned only the boundary and the divergence it hid was
  invisible to `npm run verify`.
- **A `timeout` outcome says "at least the budget" and stops there**, so a store
  that missed by a second and one that would still be running read identically —
  which is exactly what a future revision of a ceiling needs to know. ADR-0039
  adds `readMs` to `TrustStoreOutcome` for that, so the next revision reads the
  number off an ordinary run instead of a diagnostic build.
- A row's ceiling and its pinned copy in `subprocess-boundary.test.ts` must
  change in the same commit, or CI goes red — which is the intended cost of
  touching a budget.
