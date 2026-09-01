# ADR-0034: The `tls` probe hands the anchor it observed to the rest of the run

- **Status:** Accepted — retroactive write-up. The decision was made and landed
  on 2026-08-28 in `7fb050d` ("Let the tls probe hand the anchor it observed to
  the rest of the run"), whose message closes with "ADR-0034 records the seam";
  the record itself slipped past M4's docs pass, and the code's citations
  arrived before it did. Nothing below is new reasoning
- **Date:** 2026-09-01 (decision: 2026-08-28)
- **Deciders:** Bogdan Dzekic

## Context

M4's cross-check answers one question: is the root that terminated a TLS chain
present in the stores this machine and its runtimes actually trust. Answering it
needs the root.

The `tls` probe is the only code that ever sees that root. Until this decision it
saw it, classified it (`classifyRoot`, `issuancePath`, `RootVerdict`), emitted a
finding about it, and dropped it. The `truststore` probe would therefore have had
to re-fetch and re-parse every chain to learn what `tls` already knew — slower,
and a second place for the classification to drift away from the first.

The classification is not trivial arithmetic that two call sites will
independently agree on. Which certificate is "the anchor" depends on the
*issuance path*, not on the last element of the presented array: off-path padding
is not a chain's anchor, and ADR-0026's whole subject is that the distinction is
attackable. Two derivations of it would disagree after any edit to
`issuancePath`, and the disagreement would be invisible — the findings would say
one thing and the blocker correlation another.

## Decision

**`evaluateChain` returns the anchor it observed alongside its findings, and the
run carries that observation on `ProbeContext` for the `truststore` probe to
correlate against.**

- `evaluateChain` returns `{ findings, anchor }` instead of `Finding[]`.
- **The anchor is an observation, not a finding.** It carries no severity and no
  remediation, because on its own it is not actionable; it becomes actionable
  only when the `truststore` probe puts it beside a store listing.
- `ObservedAnchor` is declared in `engine/index.ts` beside `ProbeContext`, with
  its unions spelled inline rather than importing `RootClass`, because both
  probes need the type and `engine/` may not gain an edge into `probes/`.
- **`ProbeContext.observedAnchors` is required, not optional.** That is the
  entire mechanism: a required field makes the typechecker enumerate every
  construction site, so no probe harness can quietly build a context without one
  and no test can drift into exercising a shape production never sees.
- The run has **one** mutation of that array, in `src/probes/tls/index.ts`: one
  push per captured path, so a host seen direct *and* through a proxy is two
  observations. `evaluate.ts` keeps touching nothing but its arguments, and the
  mutation happens at the I/O edge where this repo puts them.
- The anchor is derived from the verdict that was just made, in a named
  `observedAnchor()` helper, rather than re-derived later. `anchorClass` reads
  `verdict.class` rather than running a second reason-to-class lookup.
- The terminus is the last certificate on the *issuance path* — the one
  `classifyRoot` reasoned over.
- `der` is present only for `self-signed-anchor-not-bundled`, the one reason
  under which the peer presented the anchor itself. Everywhere else the anchor
  was named and never sent, so the DN is the only identity there is.
- `truststore` is registered **last** for this reason, and the report then reads
  "here is the chain the network presented, and here is whether your runtimes
  trust it".
- The consumer is `correlate()` in `probes/truststore/evaluate.ts`: byte identity
  is proof, an issuer DN matching the missing anchor's subject is the weaker
  claim available when the peer sent no root at all, and it is reported as the
  weaker claim rather than rounded up.

## Alternatives considered

- **Re-fetch and re-parse the chains in the `truststore` probe.** Rejected: a
  second network round trip per target for data the run already has, and a second
  copy of the anchor derivation that can drift from the one that produced the
  findings.
- **Emit the anchor as a finding and let the cross-check read the finding
  stream.** Rejected: this repo's rule is that the `remediation` gets written
  before the check, and there is no remediation for "we saw a root" — it is not
  actionable until a store listing sits next to it. Findings are the report's
  vocabulary, not an intra-run bus.
- **Make `observedAnchors` optional.** Rejected: an optional field is one a
  harness can omit, which is precisely the shape production never has. Required
  is what made the typechecker walk all eight construction sites and all 32
  `evaluateChain` call sites in one pass.
- **Derive the terminus inline in `evaluateChain`, as the design wrote it.**
  Rejected on the boring reason that it adds a dozen lines to an
  already-long function — and the named helper gives the public-verdict early
  return somewhere to narrow `anchorClass` without a cast, which is what keeps
  `as` out of a file the guardrails care about.
- **Run a second reason-to-class lookup for `anchorClass`.** Rejected: a second
  table is a second thing to keep in step with `public-roots.ts`, and this one has
  no reason to differ from the classification that already ran.
- **Throw on an undefined terminus, as `classifyRoot` does in the equivalent
  spot.** Rejected: this is an observation channel, and it should not take down a
  run whose findings are already computed. It returns `null`.
- **Always carry the anchor's DER.** Rejected: outside
  `self-signed-anchor-not-bundled` the peer never sent the root, so any bytes here
  would be bytes portcall invented, and the cross-check would correlate on them
  as if they were proof.

## Consequences

- The cross-check's strongest evidence class exists at all: a `blocker` that says
  "this exact root terminated a live chain and your Node runtime does not have
  it", with `host`, `connection` and `match` beside it.
- **One purity guarantee in `probes/tls/evaluate.ts` now rests on erasure rather
  than on a grep.** The file gained a type-only import from `engine/index.ts`,
  which transitively imports `node:process`; the `x509-parse-only` guardrail's
  scan is textual, so it cannot see through that. The import is erased by
  `verbatimModuleSyntax` and `consistent-type-imports`, and a comment at the
  import site says so — but it is the one place in that directory where the
  guarantee is weaker than the rest of the file enjoys, and a reviewer should
  know it.
- A second `ProbeContext` anywhere in a run silently breaks the seam, since the
  observations would land on an array nobody reads;
  `test/integration/tls-harness.test.ts` names this explicitly.
- ADR-0038 later has to reorder the missing-root DN truncation around the
  correlated anchor, because a correlation that names one anchor next to a list of
  five others describes two different certificates.
- ADR-0031 bounds what the correlation may *say*: a root the machine has and a
  runtime lacks is described factually, never as "a corporate root".
