# ADR-0023: The `tls` probe discovers its proxy from environment variables only

- **Status:** Accepted
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

The `tls` probe's second-most valuable finding is `tls.intercepted-via-proxy`:
capture the chain the endpoint presents directly, capture it again through the
proxy, and report that the two differ. That claim depends on nothing but bytes
— two different certificates for one endpoint — which makes it the most robust
thing the probe can say. It also requires the probe to know a proxy to tunnel
through.

The `proxy` probe already answers "which proxy would a client use for this
endpoint", and it answers it thoroughly (M2): a profile-declared PAC URL first,
then `HTTPS_PROXY`/`HTTP_PROXY`, then WPAD discovery, with `NO_PROXY` bypass
applied across all three legs and PAC scripts evaluated per endpoint inside a
terminable Worker realm (ADR-0017, ADR-0018). That machinery exists, it is
tested, and it is right there in the same process.

Reusing it, though, means running it *again*. The PAC legs are not a lookup;
they are an evaluation — fetch the script, spin a Worker, evaluate
`FindProxyForURL(url, host)` once per endpoint, parse the result string, and
handle the inconclusive cases the M2 design enumerates. The proxy probe already
paid that cost this run, and its results are not exposed as data: `runProxy`
returns `Finding[]`, deliberately, because a probe's output is findings. Making
the routes available to another probe means either a shared cache in the engine
or the tls probe evaluating the PAC a second time.

There is a scope question underneath the plumbing one. The proxy probe asks
"what will a client do?" and has to model the whole discovery chain to answer
honestly. The tls probe asks something narrower: "is there a second path to
this endpoint worth capturing a chain over?" A false negative there costs one
comparison finding on a network where the operator can set the variable and
re-run; it does not make any other finding wrong.

## Decision

`src/probes/tls/proxy-env.ts` exposes one pure function,
`discoverEnvProxy(env)`, which reads `HTTPS_PROXY` then `HTTP_PROXY` (each in
either case, trimmed, empty treated as unset) and returns a host and port or
`null`. No PAC. No WPAD. No OS-native settings — those were already a v1
non-goal (ADR-0015).

`HTTPS_PROXY` leads unconditionally, which is a simplification of the proxy
probe's rule rather than a departure from it: that probe picks the variable by
the endpoint's port, and every capture this probe makes is a TLS capture, so
the port branch has one answer. The parsing is the proxy probe's
`parseProxyUrl` behaviour — scheme optional, port defaulted by scheme, and only
`.hostname`/`.port` ever read off the parsed URL, never `.username`/
`.password`, so an embedded credential cannot reach a finding, a socket or a
header (SPEC.md §4).

`env` is a parameter, not a read of `process.env`. Everything under
`src/probes/tls/` is banned from importing any `node:` module
(`test/guardrails/x509-parse-only.test.ts`), and the environment is input:
input arrives at the edge, in `runTls`'s default parameter.

`NO_PROXY` is not consulted here either. That is not an oversight — see the
consequences.

## Alternatives considered

**Reuse the proxy probe's full discovery, by exporting its routes.** The
honest version of "use what M2 built". Rejected because it makes one probe's
internals another probe's input, which is the coupling the registry is designed
to avoid: probes are independent `(profile, environment) => Finding[]`
functions run in sequence, and the moment `tls` depends on `proxy` having run
first, the registry order stops being a presentation choice and becomes a data
dependency. The engine would need a place to put the shared state, and a probe
that errored would silently change another probe's findings.

**Evaluate the PAC a second time, inside the tls probe.** No new coupling, but
it doubles the most expensive and most dangerous thing portcall does — running
a customer's script — for a *routing hint*. Rejected on cost and on blast
radius: ADR-0017 and ADR-0018 exist because PAC evaluation needed a terminable
Worker in a fresh realm to be safe at all, and running it twice per run doubles
that exposure to buy a proxy address the operator can supply in an environment
variable.

**Read OS-native proxy settings (WinINET, `networksetup`, GSettings).**
Rejected in ADR-0015 for v1, and nothing here changes that: it means shelling
out or reading a registry on a machine portcall does not own.

**Skip the proxied capture entirely and rely on `tls.private-root` from the
direct path.** Tempting, and it would have removed this decision. Rejected
because the two findings say different things: a private root on the direct
path shows the chain is not publicly rooted, while a *difference* between the
paths shows the proxy is re-signing, and only the second one settles an argument
with a proxy team that says its appliance is in bypass for this destination.

## Consequences

On a network configured only by PAC or WPAD, the tls probe captures the direct
path and says nothing about the proxied one. That is a real gap, and it is the
common case in large enterprises. It is acceptable because the direct capture
still produces every chain verdict, and because an operator who wants the
comparison can re-run with `HTTPS_PROXY` set — a one-line instruction that the
remediation text can carry when this is worth doing.

`NO_PROXY` is not honoured, which means that on a network where an endpoint is
bypassed the probe may attempt a tunnel a real client would not use. The
consequence is bounded: the proxy either tunnels (and the comparison is a valid
observation about what that proxy does to that endpoint) or refuses, which is
reported as `tls.capture-failed-tunnel` at `unknown` severity and asserts
nothing about the endpoint. Honouring it would mean importing the proxy probe's
`no-proxy` matcher into a directory that must stay `node:`-free and pure — not
impossible, and the right follow-up if this ever produces a confusing report.

Re-open when a customer profile shows PAC-only configuration *and* the
comparison finding is the one they need. The shape of the fix is known: the
engine grows a place for discovered routes, and the proxy probe writes to it.
That is a change to the engine's contract, so it gets its own ADR.
