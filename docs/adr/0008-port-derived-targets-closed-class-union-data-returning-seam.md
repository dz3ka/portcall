# ADR-0008: Port-derived targets, closed failure classes, a data seam

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

M1 is the first milestone that opens a socket, so the first that has to turn a
network outcome into a sentence an operator can act on. Three questions arrived
together, and hold only together: how a probe knows what to speak at an
endpoint, what vocabulary a failure may be described in, and how a failure
crosses from the I/O edge into the pure evaluation logic.

The constraint over all three is CLAUDE.md's: DNS, connect-refused, timeout, TLS
and HTTP are different teams and different tickets, and are never collapsed.

## Decision

**Targets are derived from the port, not declared in the schema.** The egress
probe sets `useTls = port === 443` (`src/probes/egress/index.ts:61`), and the
seam speaks HTTP only when TLS was negotiated or the port is 80
(`src/net/endpoint.ts:140`); any other bare port is a reachability check only.
No new schema field.

**Failure classes are a closed union.** `EgressClass` in
`src/probes/egress/classify.ts` has nine members — `ok`, `dns`, `refused`,
`unreachable`, `timeout`, `reset`, `tls`, `http`, `unclassified` — and
`classifyAttempt` maps a recorded `EndpointAttempt` to one of them, purely.
Every `switch` over the union is exhaustive and `@typescript-eslint/switch-
exhaustiveness-check` is an **error** here, so a tenth class fails the build at
every table not yet taught about it. `unclassified` becomes an `unknown`
finding, exiting 1 (ADR-0006).

**The I/O seam returns data, never an `Error`.** `src/net/types.ts` defines
`DnsOutcome` and `EndpointAttempt` as discriminated unions, and the
implementations under `src/net/` resolve rather than reject: a failure comes back
as `{ ok: false, phase, code, abortedBy, timing }`. The only throw is
`NetworkPolicyError` — a caller bug, not a finding (ADR-0004).

That shape enforces the standing rule that no probe may put a remote-derived
string into evidence. What crosses the seam is a machine code matching
`MACHINE_CODE`, an address `isIP` accepts, a status in 100–599 — `null` for
anything else. An `Error` carries a `message`, a TLS message embeds the peer's
certificate subject and altNames, and `text` evidence — like `remediation` —
crosses the redaction boundary verbatim (ADR-0005).

It also keeps the classes distinct, which is their point. `refused` is a host
that answered "no" — a firewall or ACL conversation; `unreachable` is routing or
NAT, owned by the network team; `reset` is a connection killed in flight, nearly
always an inline appliance. Folding any into `refused` sends the operator
confidently to the wrong desk.

Severity follows the profile's own claim: `cap()` lowers `blocker` to `degraded`
for a `required: false` endpoint — a blocker exits 2, gating a customer's CI on
something the tool works without. `unknown` is never capped.

## Alternatives considered

- **A scheme or URL field per endpoint.** Rejected: a second source of truth for
  what the port already says, and the first profile where the two disagree
  probes one thing while reporting another.
- **An open class type — a bare `string`, or an escape hatch on the union.**
  Rejected: it lets a remote-derived string become a class, the redaction leak in
  a different hat, and it disables the exhaustiveness check silently.
- **Throw typed errors and catch them at the probe boundary.** Rejected: the
  class set goes implicit in a chain of `instanceof` tests no compiler audits,
  and every caught error arrives holding a `message` one line puts in evidence.
- **One failure class, with the code as evidence.** Rejected for the boring
  reason: the operator does not know `EHOSTUNREACH` is a different team from
  `ECONNREFUSED`, and the value of the report is that they need not.

## Consequences

Adding a class is a compile error at every table that renders one — intended,
so that the finding, its title and its remediation get written with the class.
A novel errno reports `unclassified` and exits 1 rather than guessing: an
unrecognised failure costs a red build, not a wrong ticket.

One wart is accepted knowingly. `src/probes/dns/index.ts:7` imports `cap` from
`../egress/classify.ts`, across probes; forking it would leave two copies of a
rule that decides exit codes, and copies drift. Extracting `cap` to a shared
module is the obvious move once a third probe needs it — M2's proxy. No
existing record is superseded; ADR-0007 depends on the seam this one fixes.
