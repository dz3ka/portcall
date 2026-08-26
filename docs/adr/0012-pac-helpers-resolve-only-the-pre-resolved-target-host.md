# ADR-0012: PAC helpers resolve only the pre-resolved target host

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

A PAC script's `dnsResolve(host)`, `isInNet(host, pattern, mask)` and
`isResolvable(host)` helpers exist in the real PAC spec to let routing logic
depend on a name's resolved address — "send anything that resolves inside
10.0.0.0/8 direct, everything else through the proxy". A faithful
implementation would perform a real DNS lookup for whatever hostname the
script passes in.

That is also a DNS side-channel wide open to abuse. A PAC script is
attacker-influenceable content (ADR-0011's framing), and the whole reason
SPEC.md §4.3 forbids network calls to hosts the active profile does not name
is to keep portcall from becoming a tool that quietly probes an operator's
internal namespace on someone else's behalf. A script offering `dnsResolve`
real resolution could call it in a loop for `internal-host-1.corp`,
`internal-host-2.corp`, ... and read back which ones resolve here — enumerating
internal hostnames outside the profile allowlist, using portcall as the
DNS-side probe doing the enumerating.

## Decision

`dnsResolve`, `isInNet` and `isResolvable` (`src/probes/proxy/pac.ts`,
`buildHelpers`) answer only for the one host the evaluation is actually about.
The impure shell (`src/probes/proxy/index.ts`) resolves the endpoint host once,
via the already guard-permitted `systemResolver` — it is a profile endpoint,
so resolving it is already within policy — *before* entering the sandbox, and
hands the single answer in as `PacContext.resolvedTarget: { host, addresses }`.
Inside the sandbox, `dnsResolve(candidate)` and `isResolvable(candidate)`
return `null`/`false` for any `candidate` that does not case-insensitively
match `resolvedTarget.host`; `isInNet` falls back to `resolvedTarget`'s address
only when its own `candidate` argument is that same host. Every other name the
script asks about answers exactly as if it did not exist — never a real
lookup, and never a hint about which internal names are and are not resolvable
from this machine.

## Alternatives considered

- **Perform real resolution for whatever name the script supplies.**
  Rejected as the DNS side-channel described above — it turns a hostile PAC
  script into a probe of the internal namespace, in direct violation of
  SPEC.md §4.3's profile-allowlist rule, and does so silently: nothing about a
  `dnsResolve` call looks like network I/O to an operator reading a PAC
  script.
- **Resolve every hostname the script might name, up front, from a
  static analysis of the script text.** Rejected: it requires parsing
  arbitrary script logic well enough to enumerate every string literal that
  could reach `dnsResolve` — a script can build the name dynamically
  (`dnsDomainIs(host, "." + suffix)`-style construction) — so it either misses
  cases or degenerates into resolving names the static pass cannot prove are
  safe, which is the same side-channel with extra steps.
- **Disable `dnsResolve`/`isInNet`/`isResolvable` entirely (always
  return null/false).** Rejected: legitimate PAC scripts commonly write
  `if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";` for the exact
  endpoint host the probe is asking about — the single case this tool cares
  about answering correctly — and disabling the helpers wholesale would report
  a wrong `unresolved`/`direct` split for every profile PAC script using this
  common pattern.

## Consequences

A PAC script that branches on a *different* hostname's resolvability — for
example resolving an internal DNS-suffix probe host as a liveness check before
deciding routing — sees that call fail (`null`/`false`) here even where a real
browser would answer it, which can produce a wrong `PacVerdict` for that
particular script. That gap is accepted: it trades a rare correctness
mismatch against a real script for closing a live channel this project's
non-negotiables forbid outright. `pac.ts`'s module comment states the rule so
a future change to `buildHelpers` does not casually widen it back to live
resolution.

This decision is scoped tightly to the three name-resolving helpers.
`myIpAddress()`, `isPlainHostName`, `dnsDomainIs`, `localHostOrDomainIs` and
`shExpMatch` operate on caller-supplied strings or local machine state and
raise no side-channel of their own, so they are unaffected.
