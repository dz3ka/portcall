# ADR-0029: Interception severity is decided once, in the trust verdict; the chain comparison stays `degraded`

- **Status:** Accepted
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

The `tls` probe reaches the same subject — "this network is terminating your
TLS" — down two independent routes.

`evaluateChain` asks what a single captured chain anchors in, and when the
anchor is not a root the runtime ships it emits `tls.private-root`. That is a
trust judgement, and it is the one the profile has an opinion about: the
severity is `tolerated ? 'degraded' : cap('blocker', target.required)`
(`src/probes/tls/evaluate.ts:286`).

`compareChains` asks a narrower, harder question: are the bytes of the leaf seen
directly and the leaf seen through the proxy the same? Different bytes mean
something on the proxied path re-issued the certificate. This is the one
interception claim in the whole probe that rests on no trust judgement at all,
which is what makes it the finding that settles an argument with a proxy team
who believe the destination is already in decryption bypass. It emits
`tls.intercepted-via-proxy` at a fixed `degraded` (`evaluate.ts:680-682`).

A review round asked why the second one is not escalated to `blocker` under
`tls.interception_tolerated: false`, since the profile plainly says the client
will refuse a re-signed chain. The same round asked whether `tls.private-root`'s
severity expression is right, given that its tolerated branch skips `cap` while
its untolerated branch does not.

## Decision

**The interception severity is decided in exactly one place — the trust verdict
in `evaluateChain` — and `compareChains` stays profile-blind and fixed at
`degraded`.** `compareChains(direct, viaProxy, target)` takes no profile
parameter, and that is the contract, not an omission; the doc comment above it
says so (`evaluate.ts:645-649`) and a test now pins it.

`tls.private-root`'s severity expression is unchanged. `ok` would be a lie — a
tolerated interception still leaves every runtime on the machine unable to work
until the appliance CA is installed, which is a real task for a real person.
`blocker` under a tolerating profile would gate a customer's CI on a
configuration job the profile has already said it expects. The apparent
asymmetry is behaviourally nil: `cap('degraded', false) === 'degraded'`
(`src/probes/shared/severity.ts:15-25`), so wrapping the tolerated branch would
be a no-op edit that makes the line longer and reads as though something changes.

Two things make escalating the comparison wrong rather than merely unnecessary.

**It would double-count.** A proxied chain that was re-signed is, by
construction, a chain anchored in the appliance's own CA — so under a strict
profile the very same host on the very same run already produces
`tls.private-root` at `blocker` from `evaluateChain`. Escalating the comparison
too reports one broken thing twice in the summary, which is the failure
`captureVerdict`'s severity comment and ADR-0024's `blocker` rejection both
exist to prevent.

**It would create a false-blocker class.** Two chains can differ while both are
publicly rooted, with nothing wrong at all: a CDN point of presence serving a
different certificate than the one the direct path hit, or a load balancer
mid-rotation. Under escalation those become `blocker` — a red CI gate on a
healthy network, which is the fastest way to teach a customer to stop believing
the tool.

## Alternatives considered

- **Thread `Pick<Profile, 'tls'>` into `compareChains` and escalate when
  interception is not tolerated.** The proposal on the table, and the reason to
  state it plainly: it is *more* code, not less. A signature change and a new
  parameter at every call site, bought with a double-count and a false-blocker
  class. The comparison's value is that it is the one claim needing no profile
  and no trust judgement; taking a profile is the one change that would cost it
  that.
- **Emit `tls.intercepted-via-proxy` at `unknown` instead.** Rejected: this
  finding is not indeterminate. Two different certificates for one endpoint is
  an observation about bytes, and ADR-0006 reserves `unknown` for a check that
  ran and could not decide.
- **Drop the comparison entirely and rely on `tls.private-root`.** Rejected:
  `private-root` needs the anchor to be identifiable, and a transparent
  appliance in front of *both* paths produces two identical, privately rooted
  chains — the comparison is what distinguishes the proxy re-signing from the
  network re-signing. It is also the finding an operator can hand to a proxy
  team without arguing about trust stores.
- **Wrap the tolerated `private-root` branch in `cap` for symmetry.** Rejected
  as a no-op edit, per the arithmetic above. Symmetry that changes no behaviour
  is churn in a file whose severity expressions a reviewer has to trust.
- **Escalate only when the proxied chain is *also* privately rooted.** Rejected:
  that is `tls.private-root`'s job, spelled a second time inside a function that
  deliberately does not classify roots, and it would need the root bundle
  threaded in on top of the profile.

## Consequences

**The decision is now contract, not commentary.** `test/tls-evaluate.test.ts:285-310`
pins it: an `it.each` over the four combinations of `interception_tolerated` ×
endpoint `required` (`:292-304`) asserts `tls.intercepted-via-proxy` stays
`degraded` in all four, alongside a parallel `evaluateChain` call asserting that
`tls.private-root` moves through `blocker`/`degraded` across the same four rows.
Read the table precisely: since `compareChains` takes no profile, the
`STRICT`/`TOLERANT` column is **decorative for the interception assertion and
load-bearing only for the `evaluateChain` one**. That is the point being pinned
— the comparison is blind to the dimension the trust verdict turns on — not an
accident of the fixture. The publicly-rooted-rotation case is pinned separately
(`:306-310`), because it is the row where escalation would have been a false
blocker.

A strict profile on an intercepted network still exits `2`: `tls.private-root`
supplies the blocker, and the comparison supplies the evidence that names the
proxy as the party doing it. Nothing about the customer-visible verdict is
softened by this decision — only where in the code that verdict is decided.

Re-open if a real profile ever needs the *comparison itself* to block on a
publicly rooted difference. That is a different finding with a different meaning
("this endpoint must present the same certificate on both paths"), and it should
arrive as its own id rather than as a severity knob on this one.
