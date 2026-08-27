# The hostile network

A `docker compose` network that is deliberately broken in the four ways
enterprise rollouts actually break (SPEC.md §10), and a suite that runs portcall
inside it and asserts portcall names each one.

This is a deliverable, not a test utility. Everything else in this repo judges a
certificate chain that somebody recorded; this judges a chain that a real proxy
is really re-signing, one hop away, right now.

It runs: six tests across the four conditions below pass on a local Docker
daemon, both against an already-warm network and from a cold `down -v` start
that makes `mitmproxy` generate its root again. It has also been observed green
on a hosted CI runner: the Linux-only `harness` job passed on `c06c8c4`.

## Running it

```sh
docker compose -f test/harness/docker-compose.yml up --wait
docker compose -f test/harness/docker-compose.yml run --rm portcall
docker compose -f test/harness/docker-compose.yml down -v
```

`--wait` is the readiness mechanism. Every service has a healthcheck that proves
its *hostile condition*, not merely that its process started, so there is no
`sleep` anywhere in the harness, the suite, or CI.

The `dns` healthcheck asks for an A record by name — `nslookup -type=a` — because
this zone is IPv4-only and AAAA is deliberately left unanswered (ADR-0030).
BusyBox's untyped `nslookup` asks A *and* AAAA and exits non-zero if either leg
fails, so it reported the resolver unhealthy while the A answer it needed was
already correct, and `up --wait` aborted on a network that worked.

The suite is never part of `npm test` or `npm run verify` — portcall's whole
premise is that it runs on a locked-down machine where nothing is installed, and
a default suite that needs Docker would skip on exactly those machines
(ADR-0025). Running `npm run test:integration` outside the network fails
immediately with the commands above in the error message.

Requires Docker with `compose` v2 (`docker compose`, not `docker-compose`).

## What each service plants

| Service | Simulates | Provokes |
|---|---|---|
| `dns` | dnsmasq answering split-horizon: public names resolving to RFC1918 inside this network | `dns.split-horizon` (degraded) |
| `origin` | the profile's endpoint, serving a chain rooted in a CA no runtime ships | `tls.private-root` (blocker, on a required endpoint whose profile does not tolerate interception) |
| `mitmproxy` | a corporate inspection appliance re-signing TLS with its own generated root | `tls.private-root` on the proxied path, plus `tls.intercepted-via-proxy` (degraded) |
| `squid` | a proxy demanding Basic authentication | `proxy.auth-required` (degraded, scheme `Basic`) and `tls.capture-failed-tunnel` with code `HTTP_407` |
| `nginx-proxy` | an appliance whose policy will not tunnel a non-443 CONNECT | `proxy.connect-rejected` (degraded — the endpoint is optional) |

Portcall never authenticates to `squid`. That is the point of having it: the
suite asserts the challenge is *reported* and that the credential the image was
built with appears nowhere in the findings (SPEC.md §4).

### Addresses

The network has a fixed subnet so that this file, `dns/dnsmasq.conf` and
`docker-compose.yml` can all be checked against each other:

| Name | Address |
|---|---|
| `dns` | 10.31.0.53 |
| `origin` | 10.31.0.20 |
| `mitmproxy` | 10.31.0.30 |
| `squid` | 10.31.0.40 |
| `nginx-proxy` | 10.31.0.50 |
| `api.anthropic.com`, `registry.npmjs.org` | 10.31.0.20 — the split horizon |

Every container that needs name resolution points `dns:` at 10.31.0.53, which
bypasses Docker's embedded resolver. That is why the service names are also in
`dnsmasq.conf`: nothing in this network resolves anything the harness did not
put there, which is what makes each answer a plant rather than an accident.

### Certificates

`origin`'s key pair is generated at image build time (`origin/generate-pki.sh`)
so the chain is fixed for the life of the image, and the root is served
alongside the leaf — portcall verifies no signatures (ADR-0021), so a chain
whose anchor is absent gets `tls.root-indeterminate` rather than a verdict.

`mitmproxy` generates its own root CA on first boot into the `mitm-ca` volume,
which is mounted read-only into the suite's container at `/pki/mitm`
(`PORTCALL_HARNESS_MITM_CA`). Tearing down with `-v` deletes it, so the next run
exercises cold-start generation again rather than reusing a root that has
already been proven to work.

None of this key material is secret. It exists for the length of a test run on a
network that exists for the length of a test run, and none of it is committed.

## Debugging a failing scenario

1. **Read the finding ids in the failure message.** `findingById` prints
   everything the run emitted when it does not find what it expected. A
   `tls.capture-failed-*` id where a chain was expected names the phase that
   died — `dns`, `connect`, `tunnel` or `tls` — and that alone usually says
   which service to look at.
2. **Logs, per service:**
   ```sh
   docker compose -f test/harness/docker-compose.yml logs mitmproxy
   docker compose -f test/harness/docker-compose.yml logs dns    # log-queries is on
   ```
3. **Check what is unhealthy** — `docker compose -f test/harness/docker-compose.yml ps`.
   A service stuck `starting` never satisfied its healthcheck, and the
   healthcheck command in `docker-compose.yml` is runnable by hand:
   ```sh
   docker compose -f test/harness/docker-compose.yml exec squid \
     curl -s -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:3128 http://api.anthropic.com/
   ```
4. **Reproduce a scenario by hand** from inside the network:
   ```sh
   docker compose -f test/harness/docker-compose.yml run --rm --entrypoint sh portcall
   # then, in the container:
   HTTPS_PROXY=http://mitmproxy:8080 node src/cli/index.ts check --profile generic-ai-tool
   ```
5. **Rebuild after editing a service config.** `origin`, `dns` and `squid` are
   built images, so `up --wait` alone will not pick up an edit:
   ```sh
   docker compose -f test/harness/docker-compose.yml up --wait --build
   ```

### Known limitations, stated rather than hidden

- **`nginx-proxy` refuses every CONNECT, not only non-443 ones.** nginx cannot
  tunnel at all — its request-line parser rejects the `host:port` target form
  and answers `400`. The "non-443" half of the condition is therefore enforced
  by *which* target the suite routes through it (the profile's `:8080`
  endpoint), not by the proxy's own policy. A stand-in that tunnelled 443 and
  refused the rest would have to be a second real proxy, which would exercise
  squid's code path again and prove nothing new.
- **The suite runs inside the network, not on the host.** That is deliberate
  (ADR-0025) — the probes need the harness's resolver and its names, and a
  host-side suite would need an `/etc/hosts` edit on the developer's machine to
  get them.
- **No TLS-version scenario.** Provoking `tls.protocol-below-minimum` needs a
  peer that will still negotiate TLS 1.0, which modern OpenSSL builds will not
  do without being compiled for it. That class is covered by the recorded-chain
  fixtures in `test/fixtures/tls/`, which can hold a protocol string no live
  handshake will produce.
