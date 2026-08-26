# ADR-0026: A bundled root counts only on the leaf's issuance path

- **Status:** Accepted — cites
  [ADR-0021](0021-peculiar-x509-lands-scoped-to-parsing-not-trust.md), which is
  unchanged
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

`classifyRoot` answers the question the whole `tls` probe exists for: does this
chain anchor in a root the runtime ships, or in one somebody installed on this
network. ADR-0021 fixed what it may use to answer — parse DER, read names,
compare bytes — and forbade every API that verifies a signature or builds a
chain. Byte identity with a bundled root was the strong half of that: bytes
cannot be forged into someone else's certificate, so a match needs no signature.

The first implementation compared bytes against **every certificate in the
presented array**. A review round found the hole: a peer sends whatever it
likes, in whatever order, and nothing forced the matched certificate to have any
relationship to the leaf. Appending one public root as padding to
`[privateLeaf, privateSelfSignedRoot]` bought a `public` verdict and silenced
`tls.private-root` — a blocker turned into an `ok`, by an attacker who only has
to append bytes that are published in every browser on earth.

The reviewer's own suggested fix — match only at `chain[chain.length - 1]` —
does not fix the reviewer's own repro. The padding in that repro *is* the last
element, so a terminus-only rule matches it and still returns `public`. Worse,
it breaks the commonest real chain shape there is: a cross-signed
`[leaf, R3, ISRG X1 (bundled), DST Root X3 (not bundled, self-signed)]` would
classify `private` and emit a false blocker on a network where every client with
ISRG X1 installed connects happily.

So the property being restored is not "the root is last". It is **"the root is
one the leaf actually leads to"**.

## Decision

`classifyRoot` first computes the leaf's **issuance path**: starting at
`chain[0]`, follow issuer DN to subject DN, collecting indices, leaf first
(`src/probes/tls/public-roots.ts:141-160`). A byte match against the bundle is
honoured **only at an index on that path**; certificates off the path are
ignored, because they are not part of this chain. With no on-path byte match,
the existing anchor logic runs against the **path terminus** — `path.at(-1)`,
not `chain[chain.length - 1]`.

The walk is total on hostile input by two rules: a self-signed certificate ends
it (it does not link back onto its own subject), and a certificate is visited at
most once, so DNs that name each other in a cycle end the walk instead of
spinning.

`RootVerdict` gains `path: readonly number[]` and `matchedIndex: number | null`,
and the reason `bundled-root-in-chain` is renamed `bundled-root-on-path` —
internal, plus one guardrail key, because `publicRoot()` emits no `reason`
evidence, so the old literal never reached a report.

**The `matchedIndex` tie-break is chain order, not path order.** The scan
iterates the presented array in index order and skips off-path indices
(`public-roots.ts:183-188`), so when two on-path certificates are both in the
bundle — a cross-signed CA sent under both its issuers — the one earlier in the
array wins. The class is `public` either way; the only observable difference is
which subject name lands as the `root` evidence of `tls.public-root`
(`evaluate.ts:595-600`). Both names are of genuine public roots on a genuine
path, so there is no wrong answer to protect against, and array order is the one
order the peer chose and a reader can reproduce with `openssl s_client
-showcerts`.

## Alternatives considered

- **Match only at the terminus.** Rejected twice over: it does not fix the repro
  it was proposed for (the padding is the terminus), and it regresses the
  cross-signed shape above into a false blocker on an ordinary network.
- **Demote every non-terminal match to `indeterminate`.** Rejected: cross-signed
  chains are not an edge case, they are the commonest shape on the public web,
  and this would turn all of them into `tls.root-indeterminate`. A probe that
  cries "could not tell" on the normal case is noise, and noise is what makes
  people stop reading the report.
- **Verify signatures and settle it properly.** Rejected because ADR-0021
  forbids `cert.verify()` and `X509ChainBuilder` outright, and that ADR's
  reasoning is untouched by this one: a second, library-owned authority on
  "public or private" that can disagree with `root-bundle.ts` without anything
  noticing is a worse defect than the residual below.
- **Ignore the padding attack as unrealistic.** Rejected for the boring reason:
  the payload is public data, the delivery is "append two kilobytes to a
  handshake", and the effect is to silence the single finding this probe was
  built to emit. Cost of the fix is one array walk over at most a handful of
  certificates.

## Consequences

**The accepted residual.** A private CA that *names* a bundled root as its
issuer, and presents that root, still reads `public`. Names and bytes cannot
tell that from a genuine chain; only a signature check can, and ADR-0021 says
this code does not do signature checks. This is the same gap ADR-0021 already
accepts on the `anchor-not-presented` path, where a copied DN is why the verdict
is `indeterminate` rather than `public`. The hole is narrowed here, not closed,
and saying so is part of the deliverable.

**ADR-0021 is cited, not amended.** It already sanctions reading "enough of each
certificate to test that an issuer DN links to the next subject DN" — this walk
is exactly that reading and nothing more. It establishes what the peer *claims*,
never that the claim is signed; no new `@peculiar/x509` API is reached for; and
root membership is still decided in one place, over bytes portcall parsed
itself. Nothing in ADR-0021 means something different after this record, which
is the test for citing rather than amending.

**Two counts now sit side by side in one finding.** `tls.private-root` and
`tls.root-indeterminate` carry both `certificates presented` and `certificates
on issuance path` (`evaluate.ts:276`, `:312`), so the padded chain above reports
`3` and `2` — the report shows the reader that one certificate was disregarded
and why the verdict is what it is. That asymmetric pair is new user-facing
surface, and the decision on where it is explained is deliberate: **the
reasoning lives here, in this ADR, because it is a consequence of this
decision and belongs with it**; the README owes one clause in its `tls` section
so a reader who never opens `docs/adr/` does not read `3` and `2` as a
contradiction. That clause is a follow-up, not part of this record.

Cost: an extra `canonicalDn` pass over the chain per verdict, which is
microseconds against a handshake, and one more thing to hold in mind when
reading `classifyRoot` — the array and the path are no longer the same list.
