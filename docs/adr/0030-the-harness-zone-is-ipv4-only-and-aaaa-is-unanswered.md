# ADR-0030: The harness zone is IPv4-only, and AAAA is left unanswered

- **Status:** Accepted — upholds
  [ADR-0025](0025-the-hostile-network-harness-is-a-real-network-run-outside-verify.md),
  which is unchanged
- **Date:** 2026-08-27
- **Deciders:** Bogdan Dzekic

## Context

ADR-0025 records the hostile-network harness as the repo's strongest piece of
evidence, and CLAUDE.md calls it "a first-class deliverable, not a test util".
Both claims had a hole in them: **the harness had never once executed.** Not in
CI, not locally. The `harness` job died every time at
`docker compose -f test/harness/docker-compose.yml up --wait` with
`dependency failed to start: container portcall-harness-dns-1 is unhealthy`,
and because four services declare `depends_on: dns: {condition:
service_healthy}`, one unhealthy container took the whole network with it. A
deliverable that has never run is a description of a deliverable.

The cause is not in dnsmasq and not in portcall. It is one word in one
healthcheck. `dns` was probed with
`nslookup api.anthropic.com 127.0.0.1`, and the `nslookup` in an Alpine image is
BusyBox's, which — given no type — issues **an A query and an AAAA query** and
fails if either leg fails. `dnsmasq.conf` plants an A record for that name and
nothing else, so the AAAA leg comes back **REFUSED**. Measured inside the
container: the command prints the correct answer `10.31.0.20`, then
`** server can't find api.anthropic.com: REFUSED`, and **exits 1**. Fifteen
retries of a correct answer later, the service is `unhealthy`.

Two further measurements bound the problem. `nslookup -type=a
api.anthropic.com 127.0.0.1` returns the same answer and **exits 0** — the flag
is supported by the BusyBox already in the image, so nothing needs installing.
And Node 22 on glibc, calling `dns.lookup(host, {all: true, verbatim: true})`
against that same resolver, returns the A address with **no error at all**:
glibc's `getaddrinfo` drops the refused AAAA half silently. So portcall's own
`dns` probe was never affected by this and never would have been. The only
broken thing was the readiness check standing in front of it.

That leaves a question the failure exposed but did not itself raise: the zone
answers A and refuses AAAA, and until now nothing said whether that was a
decision or an oversight. `dnsmasq.conf`'s own header claims "every answer below
is an answer this file put there... a plant rather than an accident". For AAAA
that sentence was simply not true.

## Decision

**Fix the healthcheck, and only the healthcheck.** The `dns` probe becomes
`test: ['CMD', 'nslookup', '-type=a', 'api.anthropic.com', '127.0.0.1']`
(`test/harness/docker-compose.yml:49`). The DNS records are byte-identical to
what they were; the harness's planted conditions are unchanged, so the network
this ADR makes bootable is the same network ADR-0025 described.

**And write the IPv4-only zone down as deliberate.** `dnsmasq.conf` gains a
comment block, and nothing else, stating that no name here has an AAAA, that an
AAAA query is therefore answered REFUSED by design, and that the healthcheck's
`-type=a` is a consequence of that and not decoration. The comment in
`docker-compose.yml` says the same thing from the other end, because the flag is
exactly the kind of detail a later reader deletes while tidying.

The property being protected is ADR-0025's: **a healthcheck proves the planted
condition holds, not that a process booted.** `-type=a` keeps the check aimed at
the split horizon — the planted name still has to answer, and still has to
answer `10.31.0.20` — while no longer failing on a query for a record the zone
was never meant to have.

## Alternatives considered

**Plant an AAAA: `address=/api.anthropic.com/::`.** The obvious symmetric fix,
and the worst of the four. It makes the resolver return a *real, wrong* v6
answer — one the `dns` probe would be right to read as a genuine answer for the
name, because it is one. The harness would then be lying to the code under test
in a way the code cannot detect, which is precisely the failure mode a planted
condition is supposed to be the opposite of.

**`filter-AAAA`.** Converts the REFUSED into an empty NODATA, which is closer to
how a v4-only network behaves in the wild and is tempting for that reason.
Rejected on evidence, not on taste: BusyBox `nslookup`'s exit status on NODATA
was **not measured**, and adopting it would mean fixing a never-executed
healthcheck with a change whose effect on that healthcheck is unknown. The
measured fix was available in the same minute.

**Install `bind-tools` and use `dig +short`.** Gives exact per-type control and a
clean exit status. Rejected for the boring reason: it is a package added to an
image to make an exit code nicer, in a repo whose first promise is that it
installs nothing. It also grows the dns image and gives the harness a second
resolver client whose behaviour nobody in this repo has characterised.

**`pidof dnsmasq`, or a TCP connect to port 53.** Would have made the container
healthy immediately. Rejected as a direct violation of ADR-0025: dnsmasq binds
its socket well before a bad config would be noticed, so process liveness is a
readiness signal that passes for a resolver serving an empty zone. That is the
exact check the original comment was written to argue against, and the fix for a
too-strict check is not a check that proves nothing.

## Consequences

- The harness boots. `up --wait` exits **0** and `docker compose ps` shows five
  services, all `(healthy)`: dns, origin, mitmproxy, squid, nginx-proxy. Every
  claim ADR-0025 makes about live evidence is now a claim something executes.
- The `dns` healthcheck is narrower than it reads. It proves the A plant, and it
  is now blind to the family it stopped asking about — acceptable because the
  zone has no v6 content to be wrong about, and dishonest to leave unlabelled,
  which is why both files carry the comment.
- **A comment cannot bind a future service, and this is the accepted residual.**
  glibc forgives the refused AAAA leg; musl is under no obligation to. Every
  container that resolves through this zone today is glibc — mitmproxy is
  `mitmproxy/mitmproxy:11.0.2`, Debian 12, glibc 2.36, and its
  `socket.getaddrinfo('api.anthropic.com', 443)` returns the three `AF_INET`
  tuples for `10.31.0.20` with no error. A service added later on an Alpine or
  other musl base could see the REFUSED surface as a resolution failure, and the
  symptom would be a scenario failing for a reason that has nothing to do with
  the condition it plants. The comment is a warning, not a guard; when that day
  comes the answer is to measure `filter-AAAA` rather than to reach for
  `address=/.../::`.
- Nothing about the probes changed, and no fixture moved. This ADR records a
  test-infrastructure decision with a user-visible consequence of exactly zero —
  which is worth saying, because the finding ids CLAUDE.md treats as API are the
  same ids before and after.
