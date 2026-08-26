# ADR-0027: A capture that timed out is its own finding, not a coded failure with no code

- **Status:** Accepted — cites
  [ADR-0024](0024-tls-chain-outcome-carries-a-tunnel-phase.md) and
  [ADR-0009](0009-probe-error-evidence-is-a-closed-class-and-a-machine-code.md),
  both unchanged
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

A TLS capture that produced no chain is reported by phase: one id each for
`dns`, `connect`, `tunnel` and `tls`, with the code the OS or the proxy gave as
evidence (ADR-0024, ADR-0009). That works because there is always a code — an
errno, an `HPE_*`, an `HTTP_407` — and the code is the detail the reader takes
to the team that owns the layer.

A timeout has no code. `src/net/tls-capture.ts:100-103` builds the failure with
`code: null` whenever the phase's abort signal fired, and the probe filled the
gap with `NO_CODE = 'unavailable'`, portcall's own stand-in string, in the
`code` evidence slot. Two things were wrong with that, and only one of them is
about the evidence.

The evidence problem is that a reader sees `code: unavailable` and cannot tell
whether the network said nothing or portcall failed to record what it said. The
worse problem is the **id, title and remediation**. A black-holed SYN reaches
`captureVerdict('connect')`, whose title is "The connection never opened, so no
certificate chain could be captured" and whose remediation is "re-run this check
once the port is reachable" (`src/probes/tls/index.ts:220-229`). Both are wrong
for a dropped packet: nothing refused the connection, silence *is* the
signature, and "reachable" is exactly the thing in question. The mislabel is in
the finding's own words, so no amount of better evidence fixes it.

`egress` had already met this and answered it: `egress.connect-timeout` is a
separate id with a deliberately phase-neutral title, carrying `phase` as
evidence and a per-phase remediation (`src/probes/egress/index.ts:243-257`).
There was no reason for `tls` to answer differently.

## Decision

One new finding id, `tls.capture-failed-timeout`, emitted by `timedOut()`
(`src/probes/tls/index.ts:327-346`): phase-neutral title ("The attempt to
capture a certificate chain timed out with no answer at all"), the phase carried
as `text` evidence, **no `code` evidence at all** — the transport had none to
give, and that silence is the finding — and a four-branch
`timeoutRemediation` (`:266-299`) naming the team per phase: resolver, firewall
rule, proxy team, inline inspection appliance.

Severity is `unknown`, never capped by `required`
(`src/probes/shared/severity.ts:10-13`), for the reason the coded path already
gives: the reachability failure underneath is reported at `blocker` by `dns` or
`egress` for the same host, and `tls` does not double-count one broken thing.

Branch order in `captureFailed` is `run-signal` → `phase-timeout` → coded
(`index.ts:301-324`). The branches are disjoint by construction, since
`tls-capture.ts` only produces `phase-timeout` with `code === null`.
`NO_CODE` stays, and now honestly means "failed with no code **and it was not a
timeout**".

## Alternatives considered

- **Add a `timeout` sentinel to the `code` vocabulary** and keep the phase id.
  Rejected: it fixes the evidence and leaves the id, title and remediation
  lying. It also puts a portcall word into a slot whose whole contract is "what
  the network said", which is the distinction ADR-0009 draws.
- **Four phase-specific timeout ids** (`tls.capture-failed-connect-timeout` and
  friends). Rejected: eight capture-failure ids for what a reader thinks of as
  two facts, and `egress` already settled that a timeout's phase travels as
  evidence. Ids are API (CLAUDE.md); eight is a lot of API to buy the same
  information the `phase` evidence already carries.
- **Report it at `blocker`, as `egress` does.** Rejected for the reason ADR-0024
  gives for the tunnel id: `egress` is the probe whose job *is* reachability, so
  a blocker there is the primary report. Here it would be the second copy.
- **Say nothing when a capture times out.** Rejected outright: a silent probe on
  the exact network condition an FDE is sent to diagnose is the failure mode
  this project exists to prevent.

## Consequences

**ADR-0024 is cited, not amended, and this is the question a reader will press
hardest.** ADR-0024 says the probe emits *one id for the phase*
(`0024-tls-chain-outcome-carries-a-tunnel-phase.md:64`), and
`tls.capture-failed-timeout` cuts across all four phases. The two hold together
because they are cutting on different axes: ADR-0024's rule is about **what
happened at a seam that answered**, and it is still exactly true of the coded
path — `tls.capture-failed-tunnel` remains the one id for a tunnel that replied.
This record is about a seam that did **not** answer, which is one fact whatever
layer it happens at, and the phase is not lost — it moves off the id and onto
the evidence (`index.ts:346`). ADR-0024's own rejection of splitting the tunnel
id in two is the same reasoning: one id where the probe's answer is one thing.
Nothing in ADR-0024 means something different after this record.

**Three phase vocabularies now coexist, deliberately.** `AttemptPhase` is
`dns | connect | tls | http` (`src/net/types.ts:16`), `TlsCapturePhase` is
`dns | connect | tunnel | tls` (`:147`), and `ProxyConnectAttempt.phase` is
`AttemptPhase | 'tunnel'` (`:104`). Each names the phases its own producer can
actually reach: the capture seam never issues a request, so it has no `http`;
the endpoint and PAC-fetch seams never tunnel, so they have no `tunnel`; the
proxy-connect attempt does both, so it has all five. Unifying them is precisely
the alternative ADR-0024 already rejected — one shared union would put `http`
into a type whose producer never speaks HTTP, and a `switch` on it would need a
branch that cannot happen. This is not a defect awaiting cleanup, and it is not
this round's to change.

**`TlsCapturePhase` was extracted as a named type to buy a compile-time
tripwire.** The evidence-kinds guardrail holds
`Record<TlsCapturePhase, true>` (`test/guardrails/probe-evidence-kinds.test.ts:143`)
and spreads its keys into the allowed `text` vocabulary (`:158`), so adding a
fifth capture phase fails `typecheck` in the guardrail rather than silently
widening what a `text` evidence value may say. The precedent is `ROOT_REASONS`
directly above it (`:131-136`); the pattern is now the house rule for any closed
vocabulary that reaches a report.

`tls.capture-failed-timeout` is new public API — additive, no id removed and no
severity changed. The hostile-network harness (ADR-0025) asserts ids and
severities against live squid and mitmproxy, which is where the distinction
between a refused tunnel and a black-holed one becomes observable rather than
argued.
