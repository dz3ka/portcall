# ADR-0020: The context-budget guard's example set now covers multi-work-package fix rounds

- **Status:** Accepted
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

The global working agreement (`~/.claude/CLAUDE.md`) already treats a `[context-guard]` hard
trip with no preceding warn as a known failure mode, named against four prior incidents
(`pr-inbox-core`, `tauri-svelte-shell`, `bosun-m1-managedapp-controller`, `issue-discovery`) and
scoped with one example shape: a multi-step Phase 7 (ADRs + mentor + cartographer + wrap bundled
into one phase).

M2 session G hit the same failure in a shape that example doesn't name: a Phase-6 fix round that
spanned five work packages (WP9–WP13, the ADR-0018 PAC-sandbox hardening) with no intermediate
`[context-guard][warn]` at all — the hard tier fired on the session's very first guard message,
after `npm run verify` following all five packages. The read-only retro
(`2026-08-26-portcall-m2.md`, `~/agent-atlas/retros/`) confirmed this is the same underlying
mechanism, not a new one, but the 5th documented occurrence and the first outside a named-phase
shape — clearing the rule-of-three gate on repeat count.

## Decision

Extend the working agreement's context-budget bullet: the "do not wait inside a multi-step phase"
guidance now names a multi-work-package fix round (a review finding that spawns several
implementation packages back to back) alongside the existing Phase-7-bundling example, cites
`portcall-m2` as the 5th corpus instance, and adds the corollary that self-estimation must happen
after every work package inside such a round — not only at the named phase's own boundary.

## Alternatives considered

- **Leave the existing wording as-is and treat this as covered by "multi-step phase" generally.**
  Rejected: the existing example set names phases (Phase 7, e.g.), and a fix round isn't a
  named phase in the pipeline — a future session pattern-matching against the example list would
  reasonably conclude a fix round is out of scope for the "don't wait" rule, exactly as session G
  did.
- **Add a new, separate bullet for fix rounds instead of extending the existing one.** Rejected as
  unnecessary duplication: the underlying mechanism (self-estimation stopping at named boundaries
  instead of every sub-step) and the remedy (estimate after every sub-step) are identical; a
  second bullet would drift out of sync with the first over time.
- **Do nothing, on the grounds that one milestone's single incident is not enough signal.**
  Rejected by the retro's own gate: this is a 5th instance of an already-tracked mechanism
  (rule-of-three cleared on repeat count alone), not a first occurrence — the machinery this
  project's working agreement runs on requires acting on it.

## Consequences

A future session running a multi-work-package fix round (design-review loopback implementing
several packages before the next verify) is now explicitly in scope for "self-estimate after every
sub-step, don't wait for the named phase boundary." This does not change portcall's own code,
tests, or milestone status — M2 was already shipped and verified before this ADR was written. The
change lives in the global working agreement, not this repo; this ADR exists per the retro's
adoption note (adopted process changes get an ADR in the repo's ADR directory citing the retro),
so the decision trail is legible from this repo even though the edited file is outside it.
