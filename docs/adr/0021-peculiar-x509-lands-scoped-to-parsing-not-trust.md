# ADR-0021: `@peculiar/x509` lands, scoped to parsing and never to trust

- **Status:** Accepted — supersedes, in part,
  [ADR-0010](0010-pac-evaluation-via-node-vm-zero-new-dependency.md)
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

ADR-0002 decided the shape of the `tls` probe a milestone before the code
existed: `node:tls` captures raw DER, and a pure function of
`(chain, profile) => Finding[]` decides what the bytes mean, so the evaluation
is fixture-testable and gives the same answer under Node and under Bun. It
named `@peculiar/x509` as the parser and said the dependency lands at M3. This
is M3, and this record is that landing.

The surface the evaluation needs is small and entirely inbound: given
leaf-first DER, read subject and issuer distinguished names, the subject
alternative names, the serial, `notBefore`/`notAfter`, and enough of each
certificate to test that an issuer DN links to the next subject DN. Nothing
in that list is a decision about trust.

That distinction is the second force. `src/net/root-bundle.ts` already answers
"is this root a public CA" by comparing fingerprints against the runtime's own
bundled Mozilla list, deliberately as data. `@peculiar/x509` also ships
chain-building and signature-verification APIs with their own notion of a trust
anchor. If the evaluation reached for those, portcall would have two paths to
the single most alarming finding it can emit — one explicit and fixture-tested,
one implicit inside a library — and they could disagree without anything
noticing.

The third force is that this ends a streak. ADR-0010 chose `node:vm` for PAC
evaluation partly because it added no dependency, and made a point of it. That
posture was right for running untrusted script; it is not a rule, and pretending
this dependency is free would be worse than flagging it.

## Decision

`@peculiar/x509` is a runtime dependency, pinned `^1.14.3`
(`package.json:42`), resolved 1.14.3, MIT. It is used to **parse DER and read
fields**, and for nothing else.

Concretely: `src/probes/tls/evaluate.ts` constructs `X509Certificate` from
`Uint8Array` and reads names, SANs, serial and validity. It does not call
`X509ChainBuilder`, `cert.verify()`, or any other API that takes or implies a
trust anchor, and it does not reach `root-bundle.ts`'s classification through
one. Root membership is decided in exactly one place, over bytes portcall
parsed itself.

**On the version.** 2.0.0 is current and is not what this pins. It removed
`reflect-metadata` from its dependencies without declaring it a peer, so a
consumer must `import 'reflect-metadata'` in its own entry point before the
first `@peculiar/x509` import or `tsyringe` throws at module load. For a module
whose entire contract is being pure and `node:*`-free, that means a
side-effecting import that patches global `Reflect` sitting at the top of the
pure file. 1.14.3 carries the polyfill as its own transitive dependency, so the
purity claim is about portcall's code and not about who imported what first.
Revisit when a 2.x declares the requirement.

**Footprint.** 18 packages, all MIT except `asn1js` (BSD-3-Clause),
`tslib` (0BSD) and `reflect-metadata` (Apache-2.0): `@peculiar/asn1-{cms, csr,
ecc, pfx, pkcs8, pkcs9, rsa, schema, x509, x509-attr}` 2.9.4,
`@peculiar/utils` 2.0.3, `asn1js` 3.0.10, `pvtsutils` 1.3.6, `pvutils` 1.2.0,
`reflect-metadata` 0.2.2, `tslib` 2.8.1, `tsyringe` 4.10.0. No native code, no
WebAssembly, no install scripts — which is what keeps ADR-0001's
single-runner cross-compile intact.

## Alternatives considered

- **Hand-roll the ASN.1/DER parsing.** ADR-0002 rejected this in the abstract;
  M3 makes the reason concrete. The fields the probe reads are the ones with
  the messiest real-world encodings — DN attribute types and string encodings,
  SAN general-name variants, `UTCTime` versus `GeneralizedTime` and the
  two-digit-year pivot. A parser that gets any of those subtly wrong emits a
  confident, wrong finding about a customer's network, which is the exact
  failure this tool exists to stop. It also wins nothing: it is not the part of
  the repo anyone is reading.
- **Let the runtime verify and report the outcome** — `node:crypto`'s
  `X509Certificate.verify()`, or handshake verification left on. Rejected
  twice over. The runtime is part of what is under test (ADR-0002), so using
  its verifier as the judge makes cross-runtime parity unfalsifiable. And a
  verification result is a boolean where the probe needs four separate
  answers: intercepted, expired, wrong SNI, private root are four different
  tickets for four different teams (`CLAUDE.md`, "code conventions"), and a
  failed handshake often means never seeing the chain that would explain it.
- **Use `@peculiar/x509`'s own trust APIs for root membership**, dropping
  `root-bundle.ts`. Rejected: it is the same mistake in a new package. The
  library's trust anchors would become a second, silent authority on "public or
  private", answering off a set portcall did not choose and cannot fixture.
- **Stay at zero new dependencies and skip or weaken the check.** Rejected:
  the intercepted-chain finding is the reason SPEC.md §7 lists a `tls` probe at
  all. Zero dependencies is not a goal the project ever stated; a short,
  audited, justified list is.

## Consequences

The dependency list goes from two to three, and the transitive count from a
handful to 18. That is a real supply-chain cost on a tool whose pitch includes
a short audit list, and it is now written down where a security reviewer will
find it rather than discovered in a lockfile.

This supersedes, in part, ADR-0010: its "zero new dependency" framing no longer
describes the project. ADR-0010's actual decision — PAC evaluation runs in
`node:vm`, not in a third-party PAC interpreter — stands unchanged and remains
Accepted, and the reasoning that got it there (an untrusted-script evaluator is
the worst possible place to add a supply-chain surface) is why this break is
narrow: a DER parser reads bytes portcall already holds.

Re-open if the probe needs something 1.14.x cannot express, such as name
constraints. Per ADR-0002 the fallback is a vendored parser, not a retreat to
the runtime's certificate object.
