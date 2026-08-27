# ADR-0031: Cross-runtime parity is a verdict claim, not a bundle claim

- **Status:** Accepted — cites
  [ADR-0002](0002-capture-with-node-tls-validate-with-peculiar-x509.md) and
  [ADR-0025](0025-the-hostile-network-harness-is-a-real-network-run-outside-verify.md),
  neither of which is superseded
- **Date:** 2026-08-27
- **Deciders:** Bogdan Dzekic

## Context

ADR-0025 put bun on the `verify` job of all three CI runners so the Node/Bun
check in `test/net-root-bundle.test.ts` would stop skipping everywhere. It
stopped skipping, and it failed — on ubuntu, macos and windows alike, the single
red test in an otherwise green suite (`net-root-bundle.test.ts:66`, 682/682/683
tests, exactly one failing on each).

It failed because what it asserted is not true. The test compared the SHA-256
fingerprint set of `tls.rootCertificates` under Node against the same set under
bun and demanded they be identical. Measured: CI's Node 22 ships **145** roots,
bun ships **121**, and the Node 24 on this machine ships **120**. The list is a
snapshot of Mozilla's CA program taken whenever each runtime cut a release, so
it diverges **Node-to-Node** as readily as Node-to-bun. No amount of pinning
fixes that; a passing version of this assertion would be an accident of two
release dates lining up, and would go red again on the next Node upgrade.

Three things are worth separating here, because the failure is not what it looks
like at first read.

**The claim in the comments was never an ADR's claim.** `src/net/root-bundle.ts`
and the test's own header both said cross-runtime parity was asserted and cited
ADR-0002 for it. ADR-0002 says no such thing. What it says (`:22-26`) is that
the evaluation must not read the *runtime's certificate objects* —
`tls.PeerCertificate`, `node:crypto`'s `X509Certificate` — because then the
answers depend on which runtime executed. `root-bundle.ts` honours that: it
re-exports PEM strings, plain data, and the evaluation parses them itself. The
falsified claim existed only in those two code comments, which cited an ADR for
something it never promised.

**What ADR-0002 does want is a claim about the answer.** "The same chain gets
the same verdict under Node and under the bun-compiled binary" is the sentence
the project is sold on, and it is a statement about `classifyRoot`, not about
the size of a bundle.

**And that sentence was being measured by nothing.** The fingerprint test hashed
PEM strings with `node:crypto`; not one line of `publicRootIndex` or
`classifyRoot` — the code that actually decides `tls.public-root` versus
`tls.private-root` — had ever executed under bun, which is the runtime that
compiles the binary a customer runs (ADR-0001).

## Decision

**Parity is asserted over the verdict, given a fixed fixture bundle.**

`test/fixtures/tls/root-verdicts.ts` builds a reference root set from the
*committed* fixtures — the anchors the recorded chains in
`test/fixtures/tls/chains/` present, re-encoded as PEM — and runs portcall's own
`publicRootIndex` and `classifyRoot` over every committed capture, direct and
via-proxy, emitting the whole `RootVerdict`: class, reason, `matchedIndex` and
`path`. `test/net-root-bundle.test.ts` imports that module and runs it in
process; `print-root-verdicts.ts` runs the same module under bun and prints the
result as one line of JSON; the test deep-compares the two. One implementation,
measured twice. Pinning the input is what makes the output comparable at all —
two runtimes classifying two different root lists could not be compared even in
principle.

The whole verdict travels, not just the class. A runtime that agreed on
`public` while disagreeing on `path` or `matchedIndex` would have a real
divergence in `canonicalDn` or the issuance walk (ADR-0026), and that is exactly
the kind of thing a `String.prototype.normalize` or `btoa` difference between
engines would produce.

**One runtime-bundle assertion survives, narrowed to the fixture anchors.** Each
root the fixtures anchor in must be present in *both* runtimes' own bundles —
`fixtureAnchorsInRuntimeBundle()` answers for the process it runs in, so Node
answers for Node and the bun subprocess answers for bun, and every value must be
`true`. This guards the residual risk the fixed bundle sets aside, and it is the
only bundle difference that reaches a customer: a root in one list and not the
other flips `tls.public-root` to `tls.private-root` for the same network. Bundle
*size* differing by twenty-five roots flips nothing until one of those roots is
the one in front of you.

The `it.skipIf(BUN === null)` gate and its loud skip message are unchanged.
Whether bun is installed is an environment question, and ADR-0025's answer to it
— install bun on the `verify` job so the claim executes somewhere — still holds.

## Alternatives considered

- **Vendor a root bundle into the repo and compare against that.** Rejected for
  the reason `root-bundle.ts` gives for shipping no copy: a vendored list drifts,
  and a stale one calls a genuinely public root "private" — the single most
  alarming finding this tool can emit, produced on a perfectly healthy network.
- **Download Mozilla's list at test time.** Rejected outright: SPEC.md §4 allows
  no network call to a host that is not in the active profile, and a test suite
  that fetches from the internet is also a test suite that fails on the
  air-gapped customer laptop this tool is built for.
- **Assert the intersection is large enough — say 100 shared roots.** Rejected:
  the threshold is arbitrary across three runtime builds (145, 121, 120) and
  would need moving every time one of them re-cut its snapshot, which is the
  same brittleness in a costume. It also still executes none of portcall's own
  evaluation under bun, so it buys nothing for the claim that matters.
- **Delete the case and keep the other three.** Rejected: that leaves the
  compiled binary's entire root-evaluation path executed by nothing, anywhere —
  which is the state ADR-0025 spent a CI job to get out of.
- **Assert only the fixture anchors and drop the verdicts.** Rejected as
  half the record: it tests the bundles and not the code, and the code is what
  ships.

## Consequences

**ADR-0002 and ADR-0025 are cited, not superseded.** Neither ever claimed
identical bundles across runtimes. ADR-0002's decision — capture with
`node:tls`, evaluate over bytes portcall parsed itself, never over the runtime's
certificate objects — is untouched and is in fact what makes this new test
possible. ADR-0025's decision — install bun on `verify` so the parity claim
executes on every runner — is untouched; only the thing being measured there
changes. The correction lands in two code comments and this record, following
the "cited, not amended" precedent of ADR-0026.

**What the test now proves, precisely.** That portcall's root evaluation is
byte-for-byte agnostic to which of the two runtimes executes it, over the four
recorded conditions. What it does not prove is that the two runtimes ship the
same roots — they do not, and demanding it was the bug.

**The anchor claim is as narrow as the fixture set.** Today every recorded chain
anchors in ISRG Root X1, so one root is checked in both bundles. A fixture
anchored in a second root widens the claim for free, and a runtime that dropped
ISRG Root X1 fails here by name, next to the existing failure in
`tls-recorded-chains.test.ts` that already says how to re-record.

**`print-root-fingerprints.ts` is deleted** and `root-fingerprints.ts` stays,
demoted to what it was always actually good for: proving the runtime's own
bundle lists no root twice. The bun half of the suite now runs the fixture
loader, zod and `@peculiar/x509` as well, which is a wider surface under bun
than before — measured working on `oven/bun:1`, byte-identical output to Node.
