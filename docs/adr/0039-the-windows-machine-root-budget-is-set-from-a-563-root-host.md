# ADR-0039: The `windows-machine-root` budget is set from a 563-root host, not a 41-root laptop

- **Status:** Accepted — upholds the principle ADR-0037 states. That record is
  cited from `src/net/os-truststore.ts:159` and `:454` and from
  `src/probes/truststore/evaluate.ts`, but it is **not yet written up** in this
  directory; what follows argues from the principle as the code documents it,
  and supersedes nothing
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

One row of the pinned command table reads the Windows machine root store by
shelling out to `powershell.exe -Command 'Get-ChildItem -Path
Cert:\LocalMachine\Root | ...'`. Its `timeoutMs` was `5_000`, and that number
came from one machine: a developer laptop carrying **41 roots**, which answers
in **~0.2 s**. Five seconds was twenty-five times the only read anyone had
timed.

Then the read ran somewhere else. On a stock `windows-latest` CI runner
(measured 2026-08-28) the same command enumerated **563 roots** and took
**42 859 ms**, of which `firstByteMs=42776` — **99.8 % of the wait is over
before the first byte of output exists**. The cost is not printing, not
parsing, and not the volume of base64 crossing the pipe. It is whatever happens
inside the store enumeration before it yields anything at all.

At `5_000` that host cannot be read, so the probe reports
`truststore.os.read-timeout` and suppresses every runtime verdict that depends
on having seen the OS store. The whole Windows leg of the trust-store probe was
therefore blind on the machine the milestone is judged on.

**The principle ADR-0037 states is not in question here; the sample behind it
was.** That decision says the row's ceiling is derived from the *healthy* read
on that platform and never from a sick environment — a store that outruns a
healthy ceiling is the finding, not a number to retune, which is why
`readTimeoutRemediation` refuses to tell a row-bound reader to raise
`--timeout`. All of that still holds. What changed is the evidence for the word
*healthy*. A stock `windows-latest` image is Microsoft's own, with no MDM, no
GPO-pushed roots and no corporate CA installed, and it already carries 563 —
which is what the CTL-driven root program actually delivers to a Windows host
that has been allowed to update itself. Corporate fleets look like that host or
heavier. **The 41-root laptop was the unrepresentative sample**, and pinning a
production ceiling to it was the error.

One escalation branch was open when this was raised, and it does not fire: *if
the read turns out to be unbounded, do not raise the number.* A later
diagnostic CI run, with the ceiling temporarily at `30_000`, measured
**completed** reads at **29 628 ms** and at **22 699 ms** (warm, same job). A
read that finishes is bounded. That run's cold read clipped at the 30 s
ceiling, so the true cold figure after the `minimalEnv()` scratch-location
amendment is **unmeasured** — known only to be at least 30 s.

## Decision

**`windows-machine-root`'s `timeoutMs` becomes `60_000`.** No other row moves,
and nothing else about the command changes.

`60_000`, and not the tighter `45_000`. Forty-five seconds is 42.9 s plus about
5 %, and it is the more principled-looking of the two: it hugs the one figure
anyone has measured to completion on a cold runner. It is rejected because that
figure was measured **before** the `minimalEnv()` amendment, and the only
post-amendment cold read available clipped at 30 s. The cold read is therefore
unbounded *in the evidence* — not unbounded in fact, but pinned from above by
no measurement at all. Leaving ~2 s of headroom against a quantity with no
measured upper bound is a coin toss, and losing it costs a full CI round trip
on three runners. `60_000` is ~1.4× the one completed cold measurement and sits
well clear of the warm band.

The equality with the CLI's own default is deliberate, not a coincidence.
`DEFAULT_TIMEOUT_SECONDS = 60` (`src/cli/args.ts:34`), and `storeBudgetMs()`
hands the child `min(row ceiling, deadline − now − STORE_BUDGET_RESERVE_MS)`.
With the ceiling equal to the whole run's budget, the deadline term is always
the smaller of the two on a default run, so `budgetMs < timeoutMs`, so the
`rowBound` test in `readTimeoutRemediation`
(`src/probes/truststore/evaluate.ts`) is false and the operator gets the
**deadline-bound** remediation — "the run budget is what cut the read short,
raise `--timeout`" — which on a default run is the true sentence. A ceiling
*above* the default would let the row-bound branch fire on a run whose own
clock was the real constraint, and that branch tells the reader not to raise
`--timeout`. Keeping the two numbers equal keeps that fork honest without a
special case.

## Alternatives considered

- **Keep `5_000` and treat a 563-root host as the finding.** This is what the
  old number implies, and it is the alternative that has to be rejected out
  loud, because ADR-0037's rule read literally endorses it. Rejected on the
  measurement: a machine a stock Microsoft image reproduces is not a sick
  machine. Shipping it means an alarming finding on a perfectly healthy fleet —
  the failure class ADR-0031 rejects when it refuses to let a genuinely public
  root be called private.
- **A cheaper command: `certutil.exe -store Root`, or reading the raw
  `HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates` blob.** Both
  need a new parser and committed fixtures, and both move a pinned row that a
  guardrail exists to hold still. The decisive objection is that **there is
  zero measurement that either is faster**: 99.8 % of the wait is before the
  first byte, which is most plausibly CryptoAPI enumerating the store rather
  than PowerShell starting up, and a different client of the same API buys
  nothing. Recorded as a real future option, gated on somebody timing it first.
- **Widen `DEFAULT_TIMEOUT_SECONDS` instead.** Slows every probe's worst-case
  hang, on every platform, for every user, to fix one store on one platform.
  And it does not fix this one: the row's own 5 s ceiling would still bind. The
  deadline-bound remediation already tells the operator the actionable thing on
  the machines where the run budget genuinely is the constraint.
- **A new `TrustStoreFailure` member, or new degradation machinery for "slow
  but healthy".** Rejected because the contract already exists and already
  fires correctly: `timeout`, with `budgetMs` separating row-bound from
  deadline-bound, is exactly this situation, and the finding it produced was
  right about everything except the threshold. The bug was one literal, and a
  literal is what should change.

## Consequences

- **On such a host a *default* 60 s run still reports
  `truststore.os.read-timeout`, and that is correct behaviour rather than a
  bug.** The run deadline, less the 2 s reserve and less whatever the four
  earlier probes spent, is smaller than a ~43 s read. The reader gets the
  deadline-bound remediation, which is true, and the operator's actual fix is
  roughly `--timeout 110`. Nobody should later "fix" this by lifting the row
  above the default; that trades a true remediation for a false one.
- **`MIN_STORE_BUDGET_MS` stays `1_000`, and that open question is closed.**
  The measured spread of a real read is 0.2 s (laptop) to 42.9 s (runner), so
  `1_000` sits below every measured read but the laptop's. Its only failure
  mode is mislabelling a sub-second read that *would* have succeeded as
  `budget-exhausted`, and reaching it needs the run to have under 3 s left — a
  run already doomed, on which one store's verdict is not the news. No further
  measurement is owed here.
- **The row and its pinned copy must change in the same commit.** The table
  sits inside the guarded region that
  `test/guardrails/subprocess-boundary.test.ts` asserts element by element,
  `timeoutMs` included. That was already learned the expensive way: the two
  were changed apart once, and `verify` went red on all three OSes for it.
- **`readMs` joins `TrustStoreOutcome` in the same change**, so the *shipped*
  code reports its elapsed read time. The next revision of this number comes
  from a normal CI run rather than a third throwaway diagnostic commit.
- **A warning to whoever revisits this: the number is set from the cold case.**
  The warm band is ~22–25 s and it will be tempting to trim `60_000` down to it
  on the strength of `22699`. Do not. The cold read is the one that reddens the
  Windows leg, and it is the one figure here that has never been measured to
  completion.
