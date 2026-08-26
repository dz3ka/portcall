# ADR-0025: The hostile-network harness is a real network, and it runs outside `verify`

- **Status:** Accepted
- **Date:** 2026-08-26
- **Deciders:** Bogdan Dzekic

## Context

Everything M3 shipped before this point judges certificate chains that somebody
recorded. `test/tls-recorded-chains.test.ts` holds a fixture matrix,
`test/tls-evaluate.test.ts` builds synthetic DER, and `test/probe-tls.test.ts`
stubs the capture seam entirely. That is the right shape for the *evaluation*
— ADR-0002 exists precisely so the verdict is a pure function over bytes — but
it means nothing in the repo had ever put portcall in front of a proxy that was
actually re-signing traffic.

SPEC.md §10 calls the `docker compose` harness "the most persuasive thing in
the repo" and CLAUDE.md calls it "a first-class deliverable, not a test util".
Both are claims about *evidence*: a fixture proves the code agrees with a file
that a person wrote to match the code, and a live MITM proxy proves the code
agrees with a middlebox that has never heard of it. The four conditions named
in §10 — mitmproxy re-signing with a generated root, squid demanding Basic
auth, split-horizon DNS, a proxy that refuses `CONNECT` — are the four that
actually kill enterprise rollouts, and the interesting property of each is that
portcall names it *specifically* rather than reporting a generic failure.

Three constraints pull against each other here:

1. **Portcall must run on a machine with nothing installed.** That is the
   entire distribution argument (ADR-0001, SPEC.md §5). A test suite that needs
   Docker is a test suite that cannot run on the class of machine this tool is
   built for.
2. **CLAUDE.md forbids closing a milestone with a skipped test.** Anything
   conditionally skipped is a permanent green lie.
3. **The probes need names.** The `tls` probe captures on port 443 by hostname;
   the interception scenario needs one name that resolves to the origin *and*
   is resolvable by the proxy that will tunnel to it. Split-horizon DNS is the
   condition being planted and also the mechanism the other conditions need.

## Decision

**A real `docker compose` network, and the suite runs inside it.**

`test/harness/docker-compose.yml` brings up five services on a fixed subnet with
static addresses: dnsmasq answering split-horizon for real public names,
an nginx origin whose chain is rooted in a CA generated at image build time,
mitmproxy, squid, and an nginx that will not tunnel. Every image is pinned to a
tag, never `latest`. Readiness is a compose healthcheck on every service, so
`docker compose up --wait` is the only synchronisation and there is no `sleep`
in the harness, the suite, or CI. mitmproxy's healthcheck checks that its
generated root CA is readable *and* that a `CONNECT` is accepted, because it
binds its listener before it has written the CA and a suite that raced that
would capture chains signed by a root about to be replaced.

The suite is a sixth, profile-gated service on the same network. It exercises
`runTls`, `runProxy` and `runDns` directly rather than the built CLI, so a
failure points at a probe rather than at argv, and it asserts on finding **ids
and severities**, which CLAUDE.md treats as API.

**It is opt-in: `npm run test:integration`, its own vitest config, never part of
`npm test` or `npm run verify`,** and `vitest.config.ts` excludes
`test/integration/**` explicitly. CI runs it in one ubuntu-only `harness` job
that dumps service logs on failure and tears the network down with `-v`.

**It fails loudly rather than skipping.** Run outside the network, the suite
throws with the three compose commands that bring it up. Retries are set to
zero.

## Alternatives considered

**Recorded fixtures only, no live harness.** Cheapest, and already most of the
M3 test suite. Rejected because it cannot fail in the way that matters: a
fixture is a transcript of what the code did on the day somebody saved it, so
it catches regressions and can never catch a wrong assumption about what
mitmproxy actually sends. The assumptions this harness has to get right are
exactly the ones a fixture would have frozen unchallenged — that mitmproxy
verifies its own upstream certificates by default and answers `502` to every
tunnel unless told otherwise, for instance, which is also the shape of a real
appliance misconfiguration.

**Mock the proxies in-process.** A fake CONNECT server on localhost would be
fast and portable. Rejected: it would be written from the same understanding of
the protocol that the code under test was written from, so both would be wrong
together. The value of squid is that nobody here wrote it.

**Put the suite in `npm run verify`, skipping when Docker is absent.** The
obvious move, and the one constraints (1) and (2) jointly forbid. `verify` has
to pass on a customer's laptop, a reviewer's fresh clone and three CI runners,
two of which have no Linux Docker daemon — so the skip would be the *normal*
path and the run the exception. A permanently skipped test in the default suite
is worse than no test: it reports pale green and nobody reads it. Separate
script, separate config, separate CI job, honest pass or fail.

**Run the suite on the host against published ports.** Rejected on names. The
interception scenario needs the *same* hostname to resolve to the origin for
portcall and for mitmproxy; from the host that requires either an `/etc/hosts`
edit — a configuration mutation on the reader's machine, which is the one thing
this project promises never to do — or binding port 443 on the host. Running
inside the network costs a container build and buys real split-horizon
resolution, real proxy environment variables and no host mutation at all.

**A three-OS matrix for the harness job.** Rejected for a boring reason: the
GitHub Windows and macOS runners have no Linux Docker daemon, so two of the
three jobs could never run. The OS-dependent behaviour this project cares
about is trust stores and filesystem writes, and the `verify` matrix covers
those on all three; nothing about a proxy re-signing TLS is host-OS dependent.

**Retry a failing scenario before reporting it.** Rejected outright. Every
condition here is planted and every service's readiness is proven by a
healthcheck, so a scenario that fails once and passes on a retry is telling us
something true about a race in the code or in the harness. Retrying converts the
most interesting failure this repo can produce into a flake nobody investigates.

## Consequences

- The four §10 conditions are now asserted against live services rather than
  described in a spec. `tls.private-root`, `tls.intercepted-via-proxy`,
  `tls.capture-failed-tunnel`, `proxy.auth-required`, `proxy.connect-rejected`
  and `dns.split-horizon` each have a scenario that provokes them for real.
- Finding ids and severities gain a second contract test that does not depend on
  a fixture anyone in this repo authored.
- The default suite keeps its property: it passes on any machine with Node, and
  it contains no conditional skips.
- CI grows a job and about a container build's worth of wall clock. It is capped
  at 20 minutes on the `binaries` job's rationale — fail, don't hang.
- The harness only runs where a Linux Docker daemon does. On macOS and Windows
  that means Docker Desktop; there is no host-side fallback and deliberately no
  pretence of one.
- The `verify` job also installs bun now. That is a consequence of the same
  no-skipped-tests rule: ADR-0002's Node/Bun root-bundle parity assertion was
  skipping on every runner, so the claim the tool is sold on was executing
  nowhere.
- A new condition is a new service plus a scenario, not a new framework. The
  next one wanted is a proxy that buffers SSE, for the streaming work SPEC.md
  §3 defers to v2.
