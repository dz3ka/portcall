# ADR-0022: Distinguished names are their own evidence kind, and they are redacted

- **Status:** Accepted — extends
  [ADR-0005](0005-redaction-is-a-typed-boundary-on-by-default.md)
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

ADR-0005 made redaction a property of the *data*, not of the call site: every
piece of evidence declares an `EvidenceKind`, and `src/redact/index.ts` decides
from the kind alone whether the value is hashed or emitted verbatim. A probe
cannot opt out, and a reviewer can answer "can this leak?" by reading the kind
rather than by auditing every string that reaches a report.

The `tls` probe is the first one whose most useful evidence is a certificate's
subject and issuer distinguished name. Those names are the whole substance of
the finding a customer runs portcall to get: `tls.private-root` is only
actionable because it can say *which* root signed the chain, and
`tls.intercepted-via-proxy` is only convincing because it can show that the
issuer differs between the two paths.

They are also, routinely, the customer's own identity. A corporate interception
appliance presents something like
`CN=Acme Corp Internal Root, O=Acme Corp, OU=Network Security` — the company
name, sometimes the business unit, occasionally the name of a specific
appliance or the engineer who generated the CA. The report is a file the
customer forwards to a vendor to explain why a rollout is stuck. Those strings
must not travel with it by default.

The existing kinds could not express this. `hostname`/`ip`/`username`/`path`
are hashed but describe something a DN is not, and reusing one of them would
make the report label read wrong and make the next reader guess. `text` is
emitted verbatim and is reserved for probe-authored prose from a closed
vocabulary — putting a peer-controlled DN there is exactly the leak
`test/guardrails/probe-evidence-kinds.test.ts` exists to prevent. `public` is
verbatim by definition.

There is a second, opposite case: a *public* CA's name. `DigiCert Global Root
CA` is already public knowledge, is the same string on every machine on earth,
and hashing it would destroy the one piece of evidence that makes
`tls.public-root` readable while protecting nothing.

## Decision

`EvidenceKind` gains `'dn'` (`src/model/finding.ts:50`): an X.509 distinguished
name, subject or issuer, as parsed from the certificate. It is a sensitive kind
— it appears in `SENSITIVE_KINDS` (`src/redact/index.ts:32`) and is therefore
hashed at the report boundary whenever redaction is on, which is by default.
Its `KIND_TAG` is `dn` (`src/redact/index.ts:43`), so a redacted report reads
`dn:3f2a…` and a reader can still tell two different issuers apart across a
report without learning either name.

A public CA's name is *not* emitted as `dn`. It is emitted as `public`, by the
one code path that has established the root is in the runtime's public bundle
(`publicRoot` in `src/probes/tls/evaluate.ts`). The classification is a
consequence of a decision the evaluation already made, never a guess about how
sensitive a string looks.

The code landed in M3 WP3 rather than in this work package, and not by choice:
`KIND_TAG` is a total `Record<EvidenceKind, string>`, so adding the kind forces
the tag and the `SENSITIVE_KINDS` question at compile time. The evaluation
could not compile without both. That is the typed boundary doing its job — a
kind with no redaction wiring is a redaction hole, and this codebase makes it
impossible to ship one.

## Alternatives considered

**Reuse `hostname` for a DN.** Most DNs of interest contain a CN that looks
like a host, so the hashing behaviour would have been right. Rejected because
the label in the report would be a lie the moment the DN is an organisation
rather than a name, because the two are hashed into the same namespace and a
reader comparing a hostname to an issuer would see a false relationship, and
because the next probe that needs a genuinely different treatment for DNs would
have to unpick it.

**Emit DNs as `text` and rely on operators to redact by hand.** Rejected
outright: it inverts ADR-0005. The whole point of the typed boundary is that
nobody has to remember.

**Redact only the parts of the DN that look identifying — hash `O=`, keep
`CN=`.** Attractive, because a partially-visible DN is far more useful to read.
Rejected because it requires parsing an attacker-influenced string into fields
at the redaction boundary and deciding, per attribute type, what is safe — a
decision that would be wrong for `OU=Bogdan's Test CA` and unmaintainable as
soon as a non-standard attribute appears. Redaction is a boundary, not a
classifier; when it has to be clever it stops being auditable.

**Do not report DNs at all.** Rejected because it deletes the probe's value.
The tool exists to replace `SELF_SIGNED_CERT_IN_CHAIN` with a sentence naming
the appliance; without the issuer there is no sentence.

**Hash public CA names too, for uniformity.** Rejected for the boring reason:
the operator reading a redacted report needs to know that the chain rooted in a
CA their runtime already trusts, and `public:DigiCert Global Root CA` tells
them that in one line. Uniformity that removes information without protecting
anything is ceremony.

## Consequences

A redacted report can now show that the direct path and the proxied path
presented certificates from two different issuers, without naming either. That
is enough to escalate internally and enough to send to a vendor, which is
precisely the split ADR-0005 was designed around.

`--no-redact` still exists and still prints the DN in full, for the operator
who is diagnosing their own network and wants the appliance's name.

The kind is API, like a finding id: a report consumer that parses `dn:` tags
depends on the tag string. Changing it later would break them.

Follow-up: the guardrails already carry the kind.
`test/guardrails/redaction-boundary.test.ts` lists `dn` in the closed table it
holds `SENSITIVE_KINDS` against, so removing it from the sensitive set fails
the suite; `test/redact.test.ts` asserts a `dn` value is hashed; and
`test/guardrails/probe-evidence-kinds.test.ts` walks the tls evaluation's
findings, so a DN that reappears as `text` fails the suite rather than the
customer's trust.
