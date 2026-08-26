# ADR-0013: Auth-scheme classification cannot construct a credential header

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §7 asks the `proxy` probe to report which auth scheme (Basic, NTLM,
Negotiate) a proxy demands on a CONNECT attempt — a genuinely useful fact for
whoever configures the tool being deployed — but CLAUDE.md and SPEC.md §4 are
explicit and absolute: the probe reports the scheme, it never authenticates.
There is no partial-credit version of this rule; constructing even one
`Proxy-Authorization` header anywhere in the code, even one this run never
sends, is the failure this project's whole trust story exists to prevent, and
it is exactly the kind of thing that starts as "just read the challenge to
report it" and drifts into "well, we already parsed the realm, might as well
build the response".

## Decision

Two things hold this rule mechanically, not just by convention.

**`classifyAuthScheme(headerValue: string | null): AuthScheme`**
(`src/probes/proxy/auth.ts`) is pure and its return type is a five-member
closed union — `'Basic' | 'NTLM' | 'Negotiate' | 'none' | 'unknown'` — with no
slot for the header's `realm` or any other parameter. It is structurally
incapable of extracting or echoing a credential: there is nowhere in the
return value for one to go, even if the function wanted to put one there. The
function reads a single line off the trimmed input looking for the
earliest-listed known scheme token and returns nothing else the header
contained.

**`src/net/proxy-connect.ts`'s `connectDetailed`** — the only code in the tree
that sends a CONNECT request to a proxy — sends exactly two headers, `host`
(the CONNECT target authority, required by RFC 7231) and `connection: close`.
There is no code path, not even a disabled one, that reads a credential or
builds an `Authorization`/`Proxy-Authorization` header. This is enforced as a
trip-wire, not left as convention:
`test/guardrails/no-credential-access.test.ts` gained two forbidden patterns —
`/proxy-authorization/i` and a literal `authorization` header-key match —
scanned across all of `src/` on every `npm run verify`, with a test asserting
the patterns actually trip on realistic offending snippets (not just that they
compile).

The raw `Proxy-Authenticate` header value crosses from `proxy-connect.ts` to
the probe layer on its own return path (`ProxyConnectDetail.proxyAuthenticate`)
specifically so `classifyAuthScheme` — the only place allowed to look at it —
is the one function standing between that header and a `Finding`.

## Alternatives considered

- **Trust code review alone to keep an `Authorization` header out of the
  tree.** Rejected for the same reason ADR-0004 rejects it for the other three
  non-negotiables: it is the status quo every burned security team has already
  seen, and a rule with no mechanism behind it decays at the twentieth call
  site, not the first.
- **Let `classifyAuthScheme` return the full parsed challenge (scheme +
  realm + nonce, etc.) and have the probe layer discard the parts it
  doesn't use.** Rejected: it moves the "never construct a credential" promise
  from "structurally impossible" to "nobody happened to use the other fields
  yet", which is exactly the drift this decision exists to close off. A closed
  five-member enum is a promise a type checker enforces; a discarded field is
  a promise a reviewer has to keep re-verifying by reading every call site.
- **Detect the scheme with a broader regex that also captures
  vendor-specific auth extensions.** Rejected as unnecessary scope: SPEC.md §7
  names exactly Basic/NTLM/Negotiate, and a scheme this table does not
  recognize reports `unknown` — an honest answer, not a guess.

## Consequences

`classifyAuthScheme`'s test suite is table-driven over the closed union
(mirroring `egress/classify.ts`'s exhaustiveness pattern) and needs no fixture
files — every case is an inline header string.

A proxy that demands a scheme outside the three named ones reports
`proxy.auth-required` with `auth scheme: unknown`, which is honest and
actionable (the operator can still see a challenge happened) without this
project claiming to recognize something it does not.

This record extends ADR-0004's guardrail-test mechanism to a fifth pattern
class and supersedes nothing.
