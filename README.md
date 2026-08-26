# Portcall

One command a forward-deployed engineer hands to a prospective customer's
platform or security team *before* a deployment. It runs inside their network,
on their machine, and answers a single question:

> Will this AI developer tool actually work here — and if not, exactly what is
> blocking it and what has to change?

It is not a diagnostic you run after the deployment fails. It is the artifact
you send ahead of the first call.

**Status:** M2. The CLI, profile loader, finding model, three report renderers
and the redaction boundary landed in M0; the `dns`, `egress` and `proxy`
probes are registered and run. The TLS and trust-store probes are M3–M4.
Binaries are unsigned until v2.

## What it checks today

Three probes, run in that order: `dns` first, because a name that does not
resolve makes every connection result downstream of it meaningless; `egress`
second; `proxy` last, because its findings — an intermediary demanding auth, a
PAC-discovered route — explain the `egress` blockers reported one probe
earlier, so the reader sees the mechanism before the explanation.

**`dns`** resolves every host the profile names — once per distinct host, not
once per endpoint — and reports:

- **the host does not resolve**, with the reason in portcall's own words
  (name not found, no address records, resolver timeout, resolver refused, or
  unclassified) next to the resolver's own code. A blocker.
- **the resolver hands back a block address** (`0.0.0.0`, loopback). That is a
  deliberate sinkhole rather than a fault, and also a blocker.
- **the host resolves to an internal address** (RFC1918, CGNAT, link-local).
  Often a legitimate corporate VIP, sometimes a transparent proxy inserting
  itself; degraded either way, and worth confirming with the zone's owner.
- **resolution is slow** — 500 ms or more, which a user notices on every request
  from a tool that re-resolves. Degraded.
- **DoH reachability**, for each resolver the profile declares: whether the
  resolver's HTTPS endpoint can be reached on 443 and, if not, which layer
  stopped it. That is reachability, not proof that DoH resolution works, and
  portcall never picks a resolver of its own — see
  [ADR-0007](docs/adr/0007-doh-reachability-is-profile-declared.md).

**`egress`** attempts every declared endpoint — resolve, TCP connect, TLS on
443, then `GET /` — and names the layer that stopped it: DNS failure, connection
refused, no route, timeout with no answer at all, reset mid-flight, TLS
handshake failure, or an HTTP status that came from an intermediary instead of
the origin. Those are different teams and different tickets, so each is its own
finding with its own remediation. A failure portcall cannot name is reported as
`unclassified` at severity `unknown` rather than guessed at.

Endpoints the profile marks optional cap at `degraded`: an endpoint the tool
works without never fails a customer's build.

**`proxy`** discovers which proxy, if any, this machine is expected to use for
each declared endpoint, and whether that proxy actually tunnels traffic to it.
Discovery follows a fixed precedence: an explicit `proxy.pac_url` in the
profile, if set, beats the `HTTP_PROXY`/`HTTPS_PROXY` environment variables,
which beat a PAC file discovered via WPAD (`http://wpad/wpad.dat`, DNS-based
only — see [ADR-0016](docs/adr/0016-wpad-discovery-is-dns-based-only-not-dhcp-option-252.md)),
which falls back to "no proxy configured" as an informational finding.
`NO_PROXY` is read and validated for syntax regardless of which leg resolves
the proxy, and a bypassed endpoint is reported as such. Once a proxy is
known, portcall tests `CONNECT` to it once per distinct `(host, port)` pair —
not once per endpoint that routes through it — and reports whether the tunnel
opens, is refused, times out, or is torn down, with the same DNS/refused/
unreachable/timeout/reset vocabulary `egress` uses, so the same failure means
the same team on either probe.

Plainly, because this is exactly the kind of thing a security team needs
stated up front: **portcall reports the auth scheme (Basic, NTLM or
Negotiate) a proxy demands on a `407` response. It never authenticates** —
see [ADR-0013](docs/adr/0013-auth-scheme-classification-cannot-construct-a-credential-header.md).

### Not yet: routing egress attempts through the discovered proxy

The `proxy` probe discovers and validates the proxy and tests whether it will
tunnel to each destination, but `egress`'s own endpoint attempts remain
**direct, and only direct** — SPEC.md §7's "each endpoint via the discovered
proxy" leg is still deferred. On a network where everything egresses through a
proxy, `egress` still reports those endpoints as blocked from a direct
attempt, and `proxy` is what explains why: the reader sees the mechanism
(`egress.http-error` or a connection failure) and then the explanation
(`proxy.reachable` or an auth challenge) one probe later, rather than a single
finding that routes the attempt through the proxy itself.

## What it does not do

- **Not a security scanner.** It does not assess the customer's posture. It
  tests whether *our* software can run.
- **No SSO / OIDC round trip.** v2.
- **No EDR, code-signing or endpoint-policy checks.** v2.
- **No streaming / WebSocket longevity checks.** v2.
- **Not a general network troubleshooter.** Everything it reports is anchored
  to a profile.

## Trust properties

These are the product. A security team that cannot satisfy itself in ten
minutes that running this is safe will not run it.

1. **Read-only.** No writes outside the working directory. No configuration
   changes, no installs, no registry or keychain writes.
2. **No credentials.** It never reads keychains, tokens, private keys, or
   browser profiles, and never prompts for a password.
3. **No telemetry, ever.** Nothing leaves the machine. The operator sends the
   report or nobody does.
4. **Redacted by default.** Internal hostnames, usernames, IPs and serial
   numbers are hashed in the emitted report. `--no-redact` exists for internal
   use and prints a warning.
5. **Auditable.** Public source. Every check has a documented rationale and
   remediation.

The `proxy` probe reports the auth scheme a proxy demands. It never
authenticates.

## Run

Requires Node.js 22.6 or newer.

```bash
npm ci
npm run verify
npx portcall check --profile generic-ai-tool
npx portcall check --profile generic-ai-tool --format json
npx portcall check --profile generic-ai-tool --format html --out portcall-report.html
```

`--out` must land inside the current working directory. That is a trust
property, not a convenience.

### Exit codes

Customers run this in their own CI, so these are API. Changing one is a
breaking change.

| Code | Meaning |
|------|---------|
| `0` | No blockers. The tool should work here. |
| `1` | Degraded: it works, with limitations. |
| `2` | At least one blocker. The tool will not work here as configured. |
| `3` | Portcall itself failed: bad arguments, unreadable profile, internal error. |

A check that ran and could not decide reports `unknown`, and `unknown` exits
`1`, not `0`. A check that could not decide is not a pass, and a pipeline that
goes green on one is the failure this tool exists to prevent.

`3` is never produced by a finding, so "your network blocks this" and "your
invocation is wrong" stay distinguishable.

### Build from source

Binaries are unsigned until v2. Until then, build it yourself:

```bash
npm ci
npm run build
node dist/cli/index.js check --profile generic-ai-tool
```

`npm run build` regenerates nothing you have to trust: it checks the embedded
profiles are in sync with `profiles/` and compiles `src/` to `dist/`. The
per-platform executables described in SPEC.md §5 are built by
`npm run build:binaries`, which needs [bun](https://bun.sh) on PATH and
cross-compiles all five targets plus their SHA-256 sums. CI builds all five on
every push and keeps them as a build artifact; signed releases come at v2.

## Why it is built this way

Every non-obvious decision has an ADR in [docs/adr/](docs/adr/) — the context,
the choice, the alternatives that lost, and why. Start with
[ADR-0004](docs/adr/0004-read-only-and-credential-free-enforced-by-guardrail-tests.md)
if what you want to know is whether the trust properties above are enforced or
merely claimed.

## License

Apache-2.0. See [LICENSE](LICENSE).
