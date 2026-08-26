# ADR-0028: The `tls` probe's silence on other ports is deliberate, and a finding would poison the exit code

- **Status:** Accepted — cites
  [ADR-0006](0006-deterministic-exit-codes-with-unknown-as-degraded.md), which
  is unchanged
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

The `tls` probe captures a chain from profile endpoints on port 443 and from no
others (`src/probes/tls/index.ts:38-45`). An endpoint the profile lists on 80,
or 8443, or 5432, is skipped entirely: no chain finding of any severity appears
for it. The rule matches the `egress` probe's, which keeps its own
`const TLS_PORT = 443` (`src/probes/egress/index.ts:28`) for the same reason —
443 is the one port that implies TLS with no scheme to say so.

A review round asked the obvious question: shouldn't the report at least *say*
it skipped something? A silent omission is how a reader ends up believing a
check ran when it did not. That is a fair instinct, and the answer is still no,
for a reason that only shows up when you follow the finding all the way to the
process exit code.

It matters where the question is asked from. Inside the probe, "I skipped this
endpoint" is a true statement about the run. At the report boundary it becomes a
`Finding`, and a `Finding` has exactly one axis for how alarming it is — the
severity — which the CLI then rolls up worst-first into a single exit code. The
report has no way to say "this is informational, do not count it", and adding one
is a much larger decision than the omission it would document.

## Decision

No finding. The probe stays silent on non-443 endpoints, and the silence is
documented in prose where a reader will meet it — `README.md:127`, "**Only port
443 is probed.**", with its reason.

**The load-bearing constraint is ADR-0006.** That record fixes the severity →
exit-code mapping as API and maps **`unknown` to `1`, degraded** — "a check that
ran and could not decide is not a pass". A `tls.endpoint-not-probed` at
`unknown` would therefore make **every profile containing a port-80 endpoint
exit `1`, permanently, on a perfectly healthy network**. Portcall's second
intended use is as a gate in a customer's CI (ADR-0006's own context), so that
is not a cosmetic wart: it is a gate that is red on day one and stays red, and
ADR-0006 already names what people do to such a gate — they append `|| true`,
and then the real blockers stop failing the build too.

`ok` is not available either. `ok` claims a check passed; this check never ran.
And ADR-0006 has already ruled on exactly this shape: an empty M0 run with no
probes registered exits `ok`, "deliberately not `unknown`: nothing was checked,
so nothing was indeterminate". *Not checked* is not *could not decide*. The
severity vocabulary has no value meaning "out of scope", the exit-code space has
no code for it, and the report's existing way of saying "this was out of scope"
is to say nothing — the same way `dns` says nothing about ports and `proxy` says
nothing about certificates.

**The secondary reason is that the finding would be unactionable.** CLAUDE.md
requires the `remediation` to be written before the check, and forbids a finding
a reader cannot act on. The only honest remediation here is "declare this port
as TLS in the profile" — and `endpointSchema` (`src/profiles/schema.ts:19-27`)
has exactly five fields, `host`, `port`, `purpose`, `required`,
`expect_streaming`, and no TLS or scheme field among them. The remediation would
name an option that does not exist.

## Alternatives considered

- **Emit `tls.endpoint-not-probed` at `unknown`.** The proposal on the table.
  Rejected on the exit-code consequence above; it converts a documentation gap
  into a permanently degraded exit for a large fraction of real profiles.
- **Emit it at `ok`.** Rejected: it puts a green line in the report for a check
  that never ran, which is a worse lie than silence — silence at least does not
  assert anything.
- **A fifth severity, or a non-finding "scope" channel in the report** listing
  what was skipped. Rejected as a new moving part with one consumer: it needs a
  model change, a renderer change in both report formats, redaction rules
  (ADR-0005) and an exit-code answer, all to carry a sentence the README already
  carries. Re-open it if a second probe ever needs the same channel.
- **Add a `tls: boolean` (or `scheme`) field to `endpointSchema`** and probe
  whatever it marks. Rejected *for this round*, not forever, and it is the most
  interesting of the alternatives. It is a change to the profile format, which
  is API in the same way ids are, and ADR-0014's bar for adding a schema field
  is that the field earns its keep. There is a plausible second consumer here —
  `egress` duplicates the same 443 constant — so a future record could land the
  field for both probes at once. Bolting it on inside a fix round scoped to
  review findings would ship the API change without that design.
- **Probe every port opportunistically and report what happens.** Rejected on
  the non-negotiables and on manners. Dialling a TLS ClientHello at a plaintext
  service produces a certificate finding about a question nobody asked, at best;
  on a customer's network, unexpected handshake attempts against arbitrary ports
  are the sort of thing that shows up in someone's IDS console during a first
  engagement.
- **Guess from the port number** (8443, 9443, 4443 are "probably TLS").
  Rejected: a guess that is right most of the time produces a confident, wrong
  finding the rest of the time, and portcall exists to stop exactly that.

## Consequences

A customer whose service listens on 8443 gets no TLS verdict for it and has to
know that. The mitigation is documentation rather than a finding, which is a
worse channel than the report — accepted knowingly, and the README says it
plainly rather than leaving the reader to infer it from an absence.

The 443 rule now lives as a constant in two probes with the same value and two
comments. That duplication is on the record here as a known cost, not an
oversight, and it is the thing that would be consolidated if the profile ever
gains a field that says which endpoints speak TLS.

Re-open when a profile field for this exists, or when a real customer profile
puts a required TLS service on another port — at which point the answer is the
schema change, still not a finding at `unknown`.
