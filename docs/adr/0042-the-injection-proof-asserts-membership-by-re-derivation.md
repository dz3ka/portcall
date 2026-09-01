# ADR-0042: The injection proof asserts membership by re-derivation, and its teeth sit in two requirements

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

`test/truststore-injected/injected-root.test.ts` is M4's three-OS proof. The
`truststore-proof` job in `.github/workflows/ci.yml` generates a throwaway
CA-shaped root, injects it into the *real* trust store of a disposable
ubuntu/macos/windows runner with that platform's own command, exports its
sha256 as `PORTCALL_TEST_ROOT_SHA256`, and runs this suite. Everything the
suite claims rests on that injection having actually landed.

It cannot rest on the injection command's *exit code*. Every platform in the
matrix has a documented way of exiting 0 while planting nothing:
`update-ca-certificates` ignores any file not named `*.crt` and still exits 0
(measured for ADR-0041); macOS's `add-trusted-cert -r trustRoot` rejects a
self-signed certificate that lacks Basic Constraints `CA:true`, which is the
bug `f0c8ccc` fixed in `generate-root.mjs`; `Import-Certificate` writes to
whichever store `-CertStoreLocation` names, and naming the wrong one is not an
error. "The step was green" and "the root is in the store" are different
statements, and this suite exists to make the second one.

The suite's requirements were not all carrying that weight. Requirement 4 —
`produces truststore.node.missing-root at degraded severity` — asserted
`missing.length > 0` and that each such finding is `degraded`. Neither half
says anything about *this* root:

- **The count.** Any machine with a locally-added anchor produces the finding.
  The development host this was measured on carried 28 such anchors when
  measured 2026-09-01; a
  corporate CI runner carries more. The assertion is satisfied identically on
  a runner where the injection silently no-opped.
- **The severity.** `evaluate.ts:767` reads
  `correlation === null || set.partial ? 'degraded' : 'blocker'`, and this
  suite passes `observedAnchors: []` in its `ProbeContext` because it never
  runs the `tls` probe. `correlate()` therefore returns `null` on every run and
  the severity is `degraded` by construction. It is worth asserting as a
  statement about the finding's shape; it is not evidence about an injection.

The negative control was run before deciding, and it is the measurement that
settles which requirements have teeth. With `PORTCALL_TEST_ROOT_SHA256` set to
64 zeros, the suite went red on **exactly one** requirement — requirement 3,
`is among the locally-added anchors the probe observed` — and green on the rest,
including requirement 4. With the variable unset, the module-scope gate throws
before a single test is collected: exit 1, zero tests collected. So the failure
mode the suite must survive is not "nobody set the variable" (the gate covers
that) but "the variable names a root the injection command did not plant", and
against that mode the proof stood on one assertion.

Reading membership off the finding itself is not available.
`missingRootFinding` (`evaluate.ts:733`) publishes a count, up to
`MAX_REPORTED_DNS` = 5 subject DNs, the store's path, a `partial` marker, and —
only when the run has an observed anchor — three correlation entries. There is
no fingerprint and no digest anywhere on it. Which certificates a
`truststore.node.missing-root` finding is *about* is not recoverable from that
finding by bytes, on purpose: the finding is one ticket per trust set, written
for an operator who needs a DN and a remediation.

## Decision

**Requirement 4 keeps its two claims about the finding and gains a third claim,
asserted against an independently re-derived set rather than against the
finding's evidence.**

`missing.length > 0` and per-finding `degraded` stay: they are what the
*finding* is asserted to say, and the severity line is the one place the suite
pins that this run's verdict is the uncorrelated one. Added beside them:

```ts
expect(missingFromNodeSha256.has(expectedRootSha256)).toBe(true);
```

`missingFromNodeSha256` is built in the existing `beforeAll`, which already
re-derives `locallyAddedSha256` from the same `osTrustStoreReader` the probe
used. The same loop now keeps each locally-added anchor's DER beside its
sha256, and one further read — `runtimeStoreReader.read(['node'], …)` — supplies
node's own stores, which are indexed with the same `certificateIndex` the
cross-check uses. What is left is `locallyAdded` minus node's trust set: the
set `runtimeFindings` calls `missing` (`evaluate.ts:991`), derived a second
time from the same two readers and never from the findings.

Two properties make that re-derivation honest rather than a re-implementation:

- **node's trust set is a union, so there is no set assembly to mirror.**
  `trustSets` finds no node store with `combines: 'replaces'` — the bundled
  roots are `standalone` and `NODE_EXTRA_CA_CERTS` is `adds-to` — so the union
  of node's readable stores *is* the single set the probe builds.
- **The read is cheap and off the hook's deadline.** The two store sweeps
  already in `beforeAll` share one 180 s deadline and a comment saying why.
  This third read is node's in-process bundle plus at most one file: a `stat`,
  not a subprocess, and it takes no deadline argument.

The wider decision this records is where the proof's teeth are allowed to sit.
Requirements 3 and 4 now both fail on a runner the root was not planted on —
though not independently, and the distinction matters. `node-bundled`'s pems
*are* `PUBLIC_ROOT_CA_PEMS` (`src/net/runtime-stores.ts:478`), the same
constant `runTruststore` takes as `publicRootPems`
(`src/probes/truststore/index.ts:45`), so `locallyAdded` has already had node's
bundle subtracted from it before the cross-check runs. On any runner that does
not set `NODE_EXTRA_CA_CERTS` — which is every leg of this repo's matrix; the
`truststore-proof` job sets no env — the re-derived set is therefore *equal* to
`locallyAddedSha256`, and requirement 4's membership check restates
requirement 3's rather than corroborating it from a second direction. What the
third read actually buys is narrower and worth stating plainly: it tracks
`trustSets` if node's set assembly ever changes, and it covers the case where
`NODE_EXTRA_CA_CERTS` *is* set, where the two sets genuinely diverge.
Requirements 2, 5 and 6 assert the shape of the edge —
which store kind was read, that DNs are carried, that java's cacerts parsed —
and deliberately do not re-assert the injection. Requirement 5's existing
truncation escape stays exactly as it is, and its comment already explains
that the injected root's DN can be capped out of a five-DN list on a CI macOS
keychain with no evidence able to save it.

## Alternatives considered

- **Add a `fingerprint` evidence entry to `missingRootFinding` and assert the
  injected root's sha256 against the finding directly.** This is the literal
  form of the requirement and it is rejected on two grounds. It is an `src/`
  behaviour change, and no `src/` change is in scope for M4's close — the
  probe's evaluation has been stable across four sessions and a test's
  convenience is not a reason to move it. Independently, it is bad for the
  product: finding evidence is the report's public surface, a digest is
  something an operator cannot act on (CLAUDE.md's "write the remediation
  before the check"), and a new evidence kind carries a redaction decision of
  the same sort ADR-0022 had to make for DNs. A test asking for it should
  re-derive instead, which is what it now does.
- **Assert the injected root's DN unconditionally in the finding's `dn`
  evidence — delete requirement 5's truncation escape.** `MAX_REPORTED_DNS` is
  5, the escape hatch that could promote a specific anchor past the truncation
  is `correlate()` (ADR-0038), and `correlate()` is `null` here for the whole
  run. A macOS runner with six or more locally-added anchors would then go red
  while the injection had worked perfectly. A proof job that reddens for
  reasons other than the thing it proves gets ignored, and then proves nothing.
- **Feed the `ProbeContext` a fabricated `ObservedAnchor` so `correlate()`
  promotes the injected root ahead of the truncation.** The suite would be
  asserting against a chain nothing captured, and it would flip the severity to
  `blocker`, contradicting the finding-shape claim the same requirement makes.
  The correlated path has a proper home: the harness suite, on a live
  intercepted chain (ADR-0041).
- **Also assert the re-derived set's size equals the finding's `missing
  anchors` count.** Tempting as a drift check, and rejected: it adds no
  injection-detection power over membership, while adding a way to go red that
  has nothing to do with injection. The hook's OS read is a *second* sweep of
  the machine's stores, so any anchor added between the probe's read and the
  hook's — or any certificate one path parses and the other does not — breaks
  an equality that membership survives.
- **Delete requirement 4 and let requirement 3 carry the proof alone.**
  Requirement 3 proves the reader saw the root. The probe *emitting the
  cross-check verdict* is a different edge, and one of the two the milestone
  claims; a suite that stops asserting the finding exists stops proving it.

## Consequences

- **The proof now fails on a runner whose injection command exited 0 and
  planted nothing** — the failure mode that is actually available on all three
  platforms, and which the negative control showed only one requirement caught.
- **Two of the six requirements carry injection teeth, three assert the edge's
  shape, the first restates the gate, and the file says which is which.** The
  block comment above
  requirement 4 records the reasoning in place, so the next reader does not
  have to infer from an assertion's absence whether it was considered.
- **The property that holds is "never falsely green", and it does not depend on
  the union tracking `trustSets` exactly.** A hash reaches
  `missingFromNodeSha256` only by way of `locallyAddedDer`, which only an
  OS store the reader actually read can put it in. So on a runner where the
  injection command exited 0 without planting, the assertion cannot pass,
  whatever node's set assembly looks like. The earlier claim that a
  `combines: 'replaces'` node store would make the union a superset and turn
  the assertion red is wrong, and is recorded here so it is not re-derived:
  under `replaces`, `trustSets` sets `bases = replacing`
  (`src/probes/truststore/evaluate.ts:610`), giving the probe
  `replacing ∪ additions`, while the union here is
  `bundled ∪ replacing ∪ additions` — and since `locallyAdded` already excludes
  `bundled`, the two `missing` sets come out *equal*. The drift does not occur.
- **One extra runtime-store read per run**, outside the 180 s deadline the two
  OS sweeps share, costing a `stat` and one small file read.
- **No `src/` change, and the suite still cannot pass on a developer machine.**
  The gate still throws rather than skips, and planting a root in a real
  machine's store remains something only a disposable CI runner does
  (SPEC.md §4, CLAUDE.md).
