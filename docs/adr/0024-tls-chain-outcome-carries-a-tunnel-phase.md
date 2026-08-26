# ADR-0024: `TlsChainOutcome` carries a `tunnel` phase of its own

- **Status:** Accepted — extends
  [ADR-0009](0009-probe-error-evidence-is-a-closed-class-and-a-machine-code.md)
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

ADR-0009 settled how a failure crosses a seam in this codebase: a **closed
class** the compiler can exhaust, plus a **machine code** as evidence. The
class is the discriminator — what the code branches on — and the code is the
detail a human reads. Neither substitutes for the other, and a probe never
sniffs a code string to decide what happened.

`TlsChainOutcome`'s failure variant had `phase: 'dns' | 'connect' | 'tls'`,
mirroring `EndpointAttempt`. But a TLS capture has a path `EndpointAttempt`
does not: when the environment names a proxy (ADR-0023) the capture runs over a
CONNECT tunnel, and `openTunnel` reports its own phases, including `tunnel` —
the proxy answered the CONNECT request itself instead of forwarding it.

`src/net/tls-capture.ts` bridged that with a `tunnelPhase()` mapper that folded
`tunnel` and `http` into `connect`, on the argument that from the capture's
point of view a refused tunnel is a transport failure before any handshake, and
that the code (`HTTP_403`, `HTTP_407`) preserved the distinction anyway.

That argument does not survive contact with the probe. The commonest
enterprise case on earth is a proxy that demands authentication, and under the
fold it reached the probe as `phase: 'connect', code: 'HTTP_407'`. A
connect-phase failure gets handed to `classifyAttempt`
(`src/probes/egress/classify.ts`), whose errno table has no entry for an HTTP
status, so it falls through to `unclassified` — and portcall would tell an
operator behind a perfectly ordinary authenticating proxy that its failure "is
one portcall does not recognise". The one distinction the fold destroyed is the
one that mattered most.

The alternative to a phase would have been to test the code string, and that is
precisely what ADR-0009 forbids: the class is the discriminator. The house
pattern is already visible in `classifyConnect`
(`src/probes/proxy/index.ts:349`), which branches on `phase === 'tunnel'` and
only then reads the status.

## Decision

`TlsChainOutcome`'s failure variant carries
`phase: 'dns' | 'connect' | 'tunnel' | 'tls'` — chronological, so a reader can
see how far the capture got. `tunnelPhase()` is deleted; the call site is a
passthrough, because the tunnel's phases *are* the capture's phases.

`TunnelOutcome` (`src/net/proxy-connect.ts`) narrows in the same change, from
`AttemptPhase | 'tunnel'` to `'dns' | 'connect' | 'tunnel'`. `openTunnel` never
runs a handshake and never issues a request, so `tls` and `http` were reachable
in the type and unreachable at runtime; a malformed CONNECT reply already
rejects into `failed('tunnel', …)` with an `HPE_*` code, which is the correct
answer. `'http'` is therefore *deleted from this path, not remapped*.
`AttemptPhase` itself is untouched — `endpoint.ts` and `pac-fetch.ts` do
produce `http`, and so do `EndpointAttempt`, `ProxyConnectAttempt` and
`PacFetchOutcome`.

`tunnel.status` stays dropped. `code` is `HTTP_${status}` deterministically at
the one place a non-2xx reply becomes an outcome, so a second field carrying
the same number would be two spellings of one fact.

The probe emits **one** id for the phase, `tls.capture-failed-tunnel`, at
`unknown`, with the code on the evidence. *(Narrowed by ADR-0027: a tunnel phase
that runs out of time emits `tls.capture-failed-timeout` instead, carrying no
`code` at all — silence has nothing to quote. The coded path is unchanged and
`tls.capture-failed-tunnel` is still its only id.)*

## Alternatives considered

**Keep the fold and let the probe read the code.** Rejected: it is the
code-sniffing ADR-0009 exists to prevent, and it would put a second, private
copy of "what does `HTTP_407` mean" in a file that has no business knowing.

**Add `status: number | null` to `TlsChainOutcome`** so the probe could match
`407` the way `classifyConnect` does. Rejected as redundant — the code already
encodes it — and because the capture seam's outcome should stay the smallest
thing that answers "did I get a chain, and if not, how far did I get".

**Give `TlsChainOutcome` the whole `AttemptPhase` union plus `tunnel`,** so
every seam in `src/net/types.ts` shares one phase vocabulary. Rejected because
uniformity would put `http` into a type whose producer never speaks HTTP, and a
`switch` on it would need a branch that cannot happen — the kind of dead code a
reviewer has to think about every time.

**Split the tunnel id in two, `tls.capture-failed-auth` and
`…-rejected`,** matching the proxy probe's `proxy.auth-required` /
`proxy.connect-rejected`. Rejected, and this is the question a future reader
will ask hardest. The proxy probe's job *is* the proxy: it is answering "what
will this intermediary do to a client", so 407 and 403 are two different
verdicts and deserve two ids at real severities. The tls probe's job is the
certificate chain, and both statuses mean exactly one thing to it — no chain
was captured through the proxied path. Two ids here would restate the proxy
probe's verdict, for the same proxy, in the same run, in a second vocabulary,
and a reader would have to work out that four findings describe two facts.

**Report the failure at `blocker`.** Rejected for the reason
`wpadUnusableFinding` gives: the reachability failure underneath is already
reported at `blocker` by `dns` or `egress` or `proxy`, and re-blockering it
double-counts one broken thing in the summary. `unknown` is the honest reading
— this check could not decide.

## Consequences

An authenticating proxy now produces a finding that names what happened and
says portcall will not answer the challenge (SPEC.md §4 — the tool reports the
scheme demanded and never authenticates), instead of an "unrecognised failure".

A `switch` over the capture's phase gains a branch, and the compiler will find
every place that needs it: `switch-exhaustiveness-check` is an error in this
repo's eslint config.

`test/net-tls-capture.test.ts` gains a stubbed-407 case beside the existing 403
one, because "the two ways an enterprise proxy says no" is exactly the pair
this phase exists to carry.

This extends ADR-0009 and supersedes nothing. It is the same rule applied one
seam further out: when a failure class is missing, add the class — do not
recover it from the evidence.
