# ADR-0007: DoH reachability is profile-declared, never resolver-chosen

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §7 asks the `dns` probe to report whether DoH is blocked, and the
failure behind that line is real: an enterprise that happily serves plain DNS on
53 will often drop 443 to public DoH resolvers, precisely so endpoints cannot
route around its filtering. A tool carrying its own DoH client then fails on a
network where every other check passes.

Answering it honestly is the hard part, because the obvious implementations each
break a non-negotiable. Deciding "is DoH blocked here" in general means picking a
resolver, and any resolver portcall picks is a host the customer never agreed to
have contacted from inside their network (SPEC.md §4, non-negotiable 3), while
answering it *thoroughly* means sending a DNS query over HTTPS — real resolution
traffic issued on the operator's behalf, by a tool whose pitch is that it only
observes.

## Decision

Portcall reports DoH reachability only for resolvers the active profile names,
and what it establishes is reachability of that resolver's HTTPS endpoint —
nothing more.

`doh_resolvers` in `src/profiles/schema.ts` is a list of bare hostnames, at most
four, defaulting to empty. `NetworkGuard` pre-permits each on `DOH_PORT` (443,
fixed by RFC 8484) in its constructor, so a declared resolver is an ordinary
profile-named host, disclosable by `permitted()` before the probe loop starts.
`checkDoh` uses the same guard-gated `EndpointProber` seam as every other
endpoint — dns → connect → tls — and `evaluateDoh` reads only `ok`, `phase` and
`abortedBy`. No request body is sent, no response parsed, no name resolved over
DoH. The verdict is defined at the TLS boundary because everything an enterprise
does to stop DoH lands at or before it. Nothing is built in; nothing falls back.

The wording is held to what was measured: the passing title says the endpoint
"is reachable", never that DoH works, and each blocked finding names the layer
that stopped it (DNS, connect, TLS) at severity `degraded`. The remediation text
deliberately does not interpolate the resolver hostname. Not for redaction's
sake: `src/cli/main.ts` puts `doh_resolvers` in `publicValues`, so a declared
resolver — the only host this text could name — passes redaction unhashed
anyway, and `remediation` bypasses the boundary regardless
(`src/redact/index.ts:95` copies it verbatim). The reason is simpler: a resolver
is per-run data, and per-run data belongs in the evidence rows, so the prose
says "the resolver named in the evidence above" and stays a constant.

## Alternatives considered

- **Drop the DoH check entirely.** Rejected: it discards a common and genuinely
  confusing failure — plain DNS works, so nobody suspects DNS, and the tool's
  own resolver is silently blocked.
- **Probe a hardcoded default resolver.** Rejected: this is exactly the
  unnamed-host outbound call the project forbids. A security team watching the
  run would see portcall contact a public resolver nobody declared, which ends
  the ten-minute review deservedly.
- **Implement RFC 8484 properly, with a query and a parsed response.** Rejected:
  it needs a request body and a response parser and the `src/net/` seam exposes
  neither — it returns addresses, status codes and machine codes, never
  peer-controlled bytes (ADR-0008). It would also issue real DNS queries on the
  operator's behalf, which is not observation.
- **Put `host:port` pairs or full DoH URLs in the schema.** Rejected for the
  boring reason: the port is fixed at 443 by the RFC and the path is never used,
  so the surface buys nothing and gives an operator two new ways to misconfigure
  a check with one degree of freedom.
- **Severity `blocker` for a blocked resolver.** Rejected: it would exit 2
  (ADR-0006) on networks entirely fine for the tool under test. Blocked DoH is a
  degradation with a workaround — use the system resolver — not a verdict that
  the tool will not work here.

## Consequences

The check is only as good as the profile: one naming no resolvers gets no DoH
signal at all, and that silence is intended — portcall has nothing to say about
a resolver the tool under test does not use. Adding one is a profile edit.

Reachability is not resolution. A middlebox that completes the handshake and
then rejects the POST still reads as reachable here, so no title, evidence value
or remediation may claim "DoH works" — this record is where that limit is
written down rather than implied. If it stops being enough for a customer, the
answer is a new ADR reopening the query question against the seam constraint,
not a quiet rewording of today's claim.
