# ADR-0038: Correlated anchors take evidence priority over alphabetical order in truststore missing-root findings

- **Status:** Accepted
- **Date:** 2026-08-31
- **Deciders:** Bogdan Dzekic

## Context

`missingRootFinding` in `src/probes/truststore/evaluate.ts` reports at most
`MAX_REPORTED_DNS` (5) of a trust set's missing anchors, deliberately: "enough
anchors to act on, few enough to read", the rest counted but not listed. The
list it slices from, `missing`, arrives sorted alphabetically by
`canonicalSubject` (`byCanonicalSubject`), for reproducibility.

`correlate()` (ADR-0034) separately ties one of those same missing anchors to
a live TLS observation — a chain the `tls` probe actually watched terminate,
by byte identity or, weaker, by issuer-name match — and that tie is what
raises the finding from `degraded` to `blocker` and prints `host`,
`connection`, and `match` evidence beside it.

The bug: the slice happened before the correlation was consulted. On any
machine with more than five locally-added anchors, an anchor with positive,
live evidence against it could sort alphabetically after the fifth entry and
be dropped from the DN list entirely — while five unrelated anchors with no
evidence at all were shown in its place. The finding still said `blocker` and
still carried `host`/`connection`/`match`, but the DN list next to that
evidence did not name the anchor the evidence was about. That is a finding a
reader cannot act on: CLAUDE.md's rule for what a finding must be.

## Decision

**`correlate()` now returns which `Anchor` it matched, and
`missingRootFinding` moves that anchor to the front of `missing` before
slicing to `MAX_REPORTED_DNS`.**

- `Correlation` gains a `matched: Anchor` field, populated in both of
  `correlate()`'s passes (byte match and issuer-name match) from the same
  `missing` entry the pass already keyed on — no new matching semantics, only
  capturing which `Anchor` produced the existing match.
- `missingRootFinding` reorders `missing` when `correlation !== null`:
  `correlation.matched` first, then every other anchor in its prior
  (alphabetical) order, unchanged. `missing.length` — the "missing anchors"
  count evidence — is unaffected; only which five entries the DN list shows
  changes.
- When `correlation === null` (no TLS observation ties to any missing
  anchor), ordering is exactly as before: alphabetical, sliced at five.

`test/truststore-injected/injected-root.test.ts` never runs the `tls` probe
(`observedAnchors: []` in its `ProbeContext`), so `correlate()` always returns
`null` there and this fix has nothing to correlate the injected root against.
On a real machine with more than five other locally-added anchors (macOS CI
keychains routinely qualify), the injected root can still be truncated out of
the DN list with no correlation signal available to save it. Its DN-evidence
assertion is scoped accordingly: it requires the injected root's DN only when
the reported DN count matches the finding's own "missing anchors" total (i.e.
the list was not truncated). When truncated, the assertion a few lines above
it — the root's sha256 is present in `locallyAddedSha256`, independently
re-derived from the real OS reader — already proves the OS-read edge that
suite exists to prove.

## Alternatives considered

- **Raise `MAX_REPORTED_DNS`.** Rejected: does not fix anything. Any
  sufficiently populated machine can exceed a larger cap too — the bug is
  that priority ignores evidence, not that the cap is too small. Chasing the
  cap treats a deliberate "few enough to read" design constraint as a magic
  number.
- **Relax the injected-root test's assertion without fixing `evaluate.ts`.**
  Rejected: would leave the real defect live — the one anchor with positive,
  live evidence silently dropped in favor of unrelated roots shown for no
  reason — against CLAUDE.md's rule that a finding a reader cannot act on is
  not worth emitting. The test-contract fix here is scoped narrowly, and only
  because that suite has no TLS observation to correlate against in the first
  place, not as a substitute for the evaluator fix.

## Consequences

**A finding's DN evidence and its `host`/`connection`/`match` evidence now
always describe the same anchor when a correlation exists.** Previously they
could describe two different anchors — the correlated one implied by
`host`/`match`, and up to five uncorrelated ones actually listed — with
nothing in the finding itself signalling the mismatch.

**No change to matching semantics, severity, or evidence shape.** `correlate`
still returns `null` under exactly the same conditions as before (ADR-0034's
`indeterminate`-class exclusion on the name-only pass is untouched); this
decision only changes which five of `missing`'s entries the DN list shows
when a correlation exists.

**ADR numbering note:** this document was requested as ADR-0033, but that
number — along with 0034, 0036, and 0037 — is already cited in
`src/probes/truststore/evaluate.ts` comments for decisions whose code has
landed but whose ADR write-ups are still pending (e.g. "Portcall does not
execute a toolchain it finds on PATH (ADR-0033)"; ADR-0034 is `correlate()`'s
own governing decision, cited above and unrelated to this one). Writing a
different decision under an already-claimed number would make those existing
citations point at the wrong document, so this ADR takes the next number with
no prior citation anywhere in the tree, 0038, rather than the requested 0033.
