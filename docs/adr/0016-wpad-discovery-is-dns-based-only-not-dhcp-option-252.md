# ADR-0016: WPAD discovery is DNS-based only, not DHCP option 252

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

WPAD (Web Proxy Auto-Discovery) defines two discovery mechanisms in practice:
a DNS lookup for `http://wpad.<domain>/wpad.dat` (this project uses the
simpler, more common `http://wpad/wpad.dat` form against the resolver's
default search domain), and a DHCP option (code 252) a client can request
during lease negotiation that hands back the PAC URL directly. Real networks
use either, and some use both with DHCP taking precedence per the spec.

The DNS path is a hostname lookup and an HTTP fetch — both already exactly
`src/net/`'s existing shape (`systemResolver`, `pacFetcher`), gated the same
way every other runtime-discovered host is (`NetworkGuard.permit()`). The DHCP
path is a different kind of operation entirely: it means either parsing the
DHCP lease information the OS already negotiated (platform-specific storage,
not exposed by a Node builtin) or sending a DHCP request of portcall's own —
which is not a TCP/HTTP call at all, sits outside `NetworkGuard`'s host/port
permission model, and would be the first UDP broadcast this tool ever sends.

## Decision

WPAD discovery is DNS-based only: `http://wpad/wpad.dat`
(`src/probes/proxy/index.ts`'s `WPAD_URL`), fetched through the same
`pacFetcher` seam and `NetworkGuard.permit()` gate as `proxy.pac_url`
(ADR-0014). DHCP option 252 is an explicit non-goal for M2, not an oversight —
recorded here so a reader comparing portcall's behavior against a browser's
(which typically tries both) understands why a network relying solely on DHCP
option 252 for WPAD will read as "no proxy" from portcall even where a browser
on the same machine would find one.

## Alternatives considered

- **Send a DHCP INFORM/request to retrieve option 252 directly.** Rejected on
  two grounds. First, `NetworkGuard`'s permission model (SPEC.md §4.3) is
  built entirely around TCP host/port pairs — "which hosts and ports were
  contacted, and why" is the report's own disclosure story (ADR-0004) — and a
  DHCP broadcast is neither a host nor a port in that sense, so admitting it
  would need new guard machinery this milestone's scope does not call for.
  Second, sending a DHCP request is itself a more invasive operation than
  anything else this tool does: it is a broadcast, not a request to a
  profile-named host, on a network segment portcall does not own.
- **Read the DHCP lease the OS already negotiated, from wherever the
  platform stores it.** Rejected for the same reason ADR-0015 rejects reading
  OS-native proxy settings: the storage location and format differ per
  platform and per OS version (a Windows lease file, `dhclient.leases` on
  Linux, a macOS-specific store), none of it exposed by a Node builtin, and
  getting the parse wrong silently produces a confidently wrong verdict.
- **Try DNS first, and only note in the report that DHCP option 252 was
  not checked.** Considered and effectively adopted in spirit — this ADR and
  the README are that note — but implemented as a documented scope boundary
  rather than a runtime warning on every run, since the gap is a constant
  property of this version, not a per-run observation.

## Consequences

A network that publishes WPAD only via DHCP option 252, with no DNS record for
`wpad` and no `proxy.pac_url` set, reads as `proxy.none-configured` from
portcall — the same known-gap shape ADR-0015 documents for OS-native settings,
and for the same underlying reason: this milestone's `NetworkGuard`-gated,
TCP/HTTP-only I/O seam does not extend to DHCP.

Re-open together with ADR-0015 if a customer engagement needs either gap
closed; both would extend the discovery precedence with an additional leg
rather than changing the ones that exist.
