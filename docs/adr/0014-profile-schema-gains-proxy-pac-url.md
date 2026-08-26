# ADR-0014: Profile schema gains one optional field, `proxy.pac_url`

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §7 names PAC/WPAD discovery and "explicit config" as two distinct legs
of proxy discovery, not one. WPAD (`http://wpad/wpad.dat`, ADR-0016) is
disabled by policy on a large share of enterprise networks — it is itself a
DNS-hijack vector, and security teams that understand that routinely turn it
off — which means a customer who runs portcall on such a network and only has
the WPAD leg gets no PAC evaluation at all, even though their environment
genuinely does route through a PAC-selected proxy whose URL is known and
published internally. `HTTP_PROXY`/`HTTPS_PROXY` (already read, see ADR-0015)
cover the simpler case of a single flat proxy, but do not cover PAC-based
routing where the decision varies per destination.

`src/profiles/schema.ts` (ADR-0003, `.strict()` throughout) had no
proxy-shaped field before M2.

## Decision

`profileSchema` gains one optional block:

```ts
proxy: z.object({ pac_url: z.string().url().optional() }).strict().optional(),
```

When `profile.proxy.pac_url` is set, the `proxy` probe treats it as the
highest-precedence discovery leg — explicit config beats environment-variable
discovery, which beats WPAD, which beats "no proxy in effect" (this ordering
recorded on its own in the WP5 implementation, not a separate ADR: it follows
directly from SPEC §7 listing explicit config as a distinct, and by
implication more authoritative, leg than automatic discovery). Unlike WPAD's
absence, a `pac_url` that fails to fetch is reported (`proxy.pac-fetch-failed`)
rather than silently falling through — an operator who wrote the URL into the
profile is asserting it should work, so a fetch failure is itself a finding,
not background noise.

## Alternatives considered

- **No schema change; rely on WPAD and env vars only.** Rejected: it fails
  SPEC.md §7's explicit requirement for an "explicit config" discovery leg, and
  leaves the common case above — WPAD disabled, PAC URL known — with no way to
  exercise PAC evaluation at all on that network.
- **A full `proxy` override block with `host`/`port`, bypassing PAC
  entirely.** Rejected as YAGNI: `HTTP_PROXY`/`HTTPS_PROXY` environment
  variables already cover the "just use this one proxy directly" case (every
  HTTP client on the machine already reads them), so a second schema-level way
  to say the same thing buys nothing and gives an operator two places that can
  disagree about which proxy is actually in effect.
- **Accept a raw PAC script string inline in the profile, instead of a
  URL.** Rejected: it couples the profile — checked into a public repo,
  embedded at build time (ADR-0003) — to a script that is genuinely
  environment-specific and may itself carry internal hostnames, which the
  profile format is not the place for. A URL is a pointer; the profile stays
  data about what to check, not the environment's own configuration.

## Consequences

`z.string().url()` rejects a malformed `pac_url` at profile load, before the
probe ever runs — consistent with ADR-0003's "fail loudly at load time" goal.

The field is optional and defaults to absent, so every profile written before
M2 continues to validate unchanged; adding PAC discovery to a profile is an
additive edit, not a breaking one.
