# Portcall

One command a forward-deployed engineer hands to a prospective customer's
platform or security team *before* a deployment. It runs inside their network,
on their machine, and answers a single question:

> Will this AI developer tool actually work here — and if not, exactly what is
> blocking it and what has to change?

It is not a diagnostic you run after the deployment fails. It is the artifact
you send ahead of the first call.

**Status:** M4 closed; M5 underway. The CLI, profile loader, finding model,
three report renderers and the redaction boundary landed in M0; the `dns`,
`egress`, `proxy` and `tls` probes are registered and run. The trust-store
probe, and the cross-check between the root observed intercepting traffic and
the stores each runtime actually reads, closed M4. M5 is packaging: two named
vendor profiles - Anthropic Claude Code and Cursor - beside the generic one
that ships today, a checksum manifest signed through Sigstore keyless signing,
and a one-command demo of the hostile harness recorded as a terminal capture.
Binaries themselves are unsigned until v2 - it is the manifest that is signed,
not the executable.

## What it checks today

Five probes, run in that order: `dns` first, because a name that does not
resolve makes every connection result downstream of it meaningless; `egress`
second; `proxy` third, because its findings — an intermediary demanding auth, a
PAC-discovered route — explain the `egress` blockers reported one probe
earlier, so the reader sees the mechanism before the explanation; `tls` fourth,
for the same reason once more: it captures a chain through whichever proxy the
environment names, and a reader should meet the intermediary before meeting the
certificate it presents. `truststore` last, because it reads the anchors `tls`
observed and answers the question they raise: does anything on this machine
actually trust them.

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

**`tls`** asks what certificate chain this machine actually receives. It
connects with verification **deliberately disabled** — the job is to observe
what the network presents, not to accept or reject it — captures the chain, and
evaluates it in-process over the DER bytes. Portcall parses certificates; it
never verifies a signature and never builds a trust path
([ADR-0021](docs/adr/0021-peculiar-x509-lands-scoped-to-parsing-not-trust.md)),
so a chain that does not carry its own root is reported as
`tls.root-indeterminate` rather than guessed at from the issuer name.

It captures once per distinct host and port, and a second time through the
proxy when `HTTPS_PROXY`/`HTTP_PROXY` names one. What it reports:

- **where the chain anchors** — `tls.public-root` when the top of the chain is
  a root the runtime's own bundle ships, `tls.private-root` when it is not. A
  private root is a blocker unless the profile sets
  `tls.interception_tolerated` or marks the endpoint optional, in which case it
  degrades: the network is terminating TLS itself, and every runtime still has
  to be told to trust the appliance CA before the tool works. Portcall ships no
  root list of its own — it reads the one its runtime was built with, and those
  snapshots differ between builds (Node 22 ships 145 roots, bun 121, Node 24
  120). What is held constant is the *answer*: the classification code is
  tested under both runtimes over the same fixed roots and must reach identical
  verdicts, and the roots the test fixtures anchor in must be present in both
  bundles
  ([ADR-0031](docs/adr/0031-cross-runtime-parity-is-a-verdict-claim-not-a-bundle-claim.md)).
- **the direct chain against the proxied one** — `tls.intercepted-via-proxy`
  (degraded) when the two differ, `tls.chain-consistent` when they do not. This
  is the one interception claim that rests on no trust judgement at all: two
  different certificates for one endpoint is an observation about bytes, and it
  is what settles an argument with a proxy team that believes the destination
  is already in decryption bypass.
- **the negotiated version**, against the profile's floor — `tls.protocol`,
  `tls.protocol-below-minimum` (blocker), and `tls.protocol-unknown` when the
  handshake reports a name portcall will not rank.
- **validity** — `tls.chain-expired` and `tls.chain-not-yet-valid` are
  blockers; `tls.chain-expiring-soon` fires 30 days out, degraded, because a
  change window in a large organisation is rarely shorter than that.
- **the name** — `tls.sni-mismatch` and `tls.leaf-no-san`, blockers, since
  modern clients reject both outright.
- **a capture that produced no chain** — `tls.capture-failed-dns`,
  `tls.capture-failed-connect`, `tls.capture-failed-tunnel` and
  `tls.capture-failed-tls`, named for the phase that died and each carrying the
  code the layer that failed reported — an errno, or the proxy's HTTP status;
  `tls.capture-failed-timeout` when a phase ran out of time instead, which cuts
  across all four — silence has no code to quote, so the phase moves onto the
  finding's evidence rather than into its id; plus
  `tls.chain-empty`, `tls.chain-unparseable` and `tls.aborted`. Every one is
  `unknown` and never a blocker: the failure underneath is already reported as
  a blocker by `dns` or `egress` for the same host, and counting one broken
  thing twice would make the summary lie about how much is wrong.

Blockers cap at `degraded` on endpoints the profile marks optional, as
everywhere else.

**Only port 443 is probed.** An endpoint the profile lists on any other port is
skipped by `tls` entirely — no chain finding, of any severity, appears for it.
Portcall has no way to know that 8443 speaks TLS until a profile says so, and
dialling a handshake at a plaintext service would answer a question nobody
asked.

### `truststore`: what this machine trusts, and what your runtimes do

**`truststore`** reads this machine's own trust store — the macOS keychains,
the Windows machine root store, or the Linux CA bundle — and the store each
runtime the profile declares actually consults, and reports the gap between
them. That gap is the failure this whole tool exists for: a laptop where the
corporate root is installed and `curl` works fine, and Node, Go, Python or Java
fails, because none of them reads the OS store the way the browser does.

- **`truststore.os.read`** names the store that was read, how many anchors
  *that store* holds, and how many of those are *locally added* — present on
  this machine and absent from the runtime's own public list. Described
  factually and never as "a corporate root": a public root merely newer than a
  runtime's bundled snapshot lands in the same set, and the finding must not
  overstate. Where the store held a certificate portcall could not parse, the
  count of those is on the finding too, so the anchor total reads as what was
  cross-checked rather than as what was there.
- **`truststore.<runtime>.missing-root`** — one clustered finding per store a
  runtime consults, listing up to five subject DNs. `degraded` on its own;
  **`blocker`** when the anchor correlates with one the `tls` probe watched
  terminate a chain this run, with the match reported as `bytes` (proof) or
  `issuer-name` (the weaker claim, when the peer sent no root at all). A
  profile that tolerates interception does **not** soften it — that setting
  says an inspecting proxy is expected, not that a root the runtime cannot
  verify against is fine.
- **`truststore.<runtime>.roots-present`**, **`.platform-verifier`** (Go on
  macOS and Windows asks the OS itself, so there is nothing to compare),
  **`.extra-ca-configured` / `.extra-ca-unreadable`** (a `NODE_EXTRA_CA_CERTS`
  or `SSL_CERT_FILE` naming a file the runtime silently ignores — the failure
  operators never find), **`.store-not-found`** listing where portcall looked,
  and **`truststore.java.store-unreadable`** for a keystore it will not open.
  Portcall never supplies a keystore password, not even the published default.
- **`truststore.os.unreadable`**, **`truststore.os.read-timeout`** and
  **`truststore.os.aborted`** are the three ways the read itself fails, and
  they stay three findings because they are three different tickets. When
  *none* of the stores could be read, portcall emits
  `truststore.crosscheck.indeterminate` and **no verdict at all** — not the bad
  one, and deliberately not the good one either. Absence of evidence must not
  print as a green "roots present".

The store read gets a fixed budget per store, cut down by whatever the run has
left, and a store that outruns it is reported rather than waited for: the
budget is the healthy read on that platform, never the sick environment's
observed duration.

**One Windows disclosure.** Enumerating the machine root store can make Windows
itself contact `ctldl.windowsupdate.com` to refresh its certificate trust list.
That is an OS behaviour triggered by reading the store, not a call portcall
makes — portcall's own network allowlist is not involved and SPEC.md §4's rule
about the calls *portcall* issues is not breached — but it is visible at a
customer's egress, so it is stated here rather than discovered in a firewall
log.

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

### Not yet: the `tls` probe finds its proxy in the environment only

The `proxy` probe has three discovery legs — a profile-declared PAC URL, the
environment variables, and WPAD. The `tls` probe's proxied capture has one: it
reads `HTTPS_PROXY`/`HTTP_PROXY` and nothing else
([ADR-0023](docs/adr/0023-tls-probe-discovers-its-proxy-from-environment-variables-only.md)).
On a network configured only by PAC or WPAD — the common case in a large
enterprise — `tls` captures the direct path, reports every chain verdict for
it, and simply says nothing about the proxied path. An operator who wants the
comparison can re-run with `HTTPS_PROXY` set.

`NO_PROXY` is not consulted on that leg either, so on a network where an
endpoint is bypassed the probe may attempt a tunnel a real client would not
use. The proxy then either tunnels — in which case the comparison is a valid
observation about what that proxy does to that endpoint — or refuses, which is
reported as `tls.capture-failed-tunnel` at `unknown` and asserts nothing about
the endpoint. The `proxy` probe reads and validates `NO_PROXY` in full.

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

The `tls` probe turns certificate verification off on its own connections, and
that is the check rather than a shortcut: a verifying client facing an
interception proxy gets an error and no chain to look at, which is the useless
outcome this tool exists to replace. Not one byte of application data is
written to those connections — the handshake completes, the chain is copied
out, the socket is destroyed — the trust judgement is moved downstream into a
pure function rather than skipped, and the same profile allowlist gates the
connection as everywhere else.

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

Three profiles ship embedded in the binary, and the `--profile` id of each is
its filename in `profiles/` with the extension dropped:

- `--profile claude-code` - Anthropic Claude Code.
- `--profile cursor` - Cursor.
- `--profile generic-ai-tool` - the endpoints almost any AI developer tool
  needs, and nothing vendor-specific.

Every endpoint in the two vendor profiles carries a `# source:` line naming the
vendor page it was read from, because declaring a host is exactly what makes
portcall connect to it. `--profile ./acme.yaml` reads a profile off disk
instead, through the same parser.

A profile is data, not code, so a new vendor arrives as a pull request against
`profiles/` rather than as a wait for the next release
([ADR-0003](docs/adr/0003-profiles-are-data-embedded-at-build-time.md)). What
that costs is a rename: the file stem *is* the published command line, so it is
treated as API from the first tag
([ADR-0043](docs/adr/0043-a-profile-filename-is-public-cli-surface.md)).

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

The released executables are unsigned until v2, and stay unsigned however
carefully you verify the release - see [Verify a release](#verify-a-release)
for what the signature does and does not cover. Building it yourself is the
other way:

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
every push and keeps them as a build artifact.

### Verify a release

A pushed `v*` tag publishes seven assets: the five executables, a
`SHA256SUMS` manifest covering all five, and `SHA256SUMS.cosign.bundle`. The
bundle holds the signature over that manifest, the short-lived Fulcio
certificate it was made with, and the Rekor inclusion proof. There is no
private key anywhere in this project: the release workflow signs through
Sigstore keyless, with a GitHub OIDC token it mints for the ~10 minutes the
signing takes
([ADR-0048](docs/adr/0048-release-checksums-are-signed-with-sigstore-keyless.md)).

Download the manifest, the bundle and the binary you want, then check the
signature on the manifest. Needs [cosign](https://github.com/sigstore/cosign)
v3 or newer:

```bash
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/dz3ka/portcall/\.github/workflows/release\.yml@refs/tags/v'
```

Then check the binary against the now-trusted manifest:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

`sha256sum` is GNU coreutils. On macOS the equivalent is `shasum -a 256
--ignore-missing -c SHA256SUMS`; in PowerShell there is no `-c` mode, so
compare `Get-FileHash -Algorithm SHA256 <file>` against the matching line by
eye. `--ignore-missing` is what lets any of them pass when you downloaded one
of the five executables rather than all of them; drop it if you have the whole
set.

**What that proves is narrow, and the narrowness is the point.** The signature
covers the *manifest*, and what it establishes is that this repository's
release workflow produced it at a `v*` tag. The executables themselves carry no
OS code signature - no Authenticode certificate, no Apple notarisation - so
Gatekeeper and SmartScreen will still object to them, and a verified manifest
does nothing to change that. Signing the executables is v2.

The two commands above are not documentation of a process nobody runs: the
release workflow runs the `cosign verify-blob` line verbatim, against the files
it is about to upload, before it uploads them. Rename that workflow file or
trigger it off something other than a `v*` tag and the certificate identity
stops matching, so the release fails there rather than shipping assets whose
published verification command does not work.

Releases are cut from a commit already green on all three OSes - `verify` runs
on ubuntu, macOS and Windows on every push - and the release workflow re-runs
`npm run verify` on the tagged commit itself before building anything, because
a tag can be pushed at a commit that never went through a pull request.

## The hostile network

`test/harness/` is a `docker compose` network that is deliberately broken in
the ways enterprise rollouts actually break, and a suite that runs portcall
inside it: `mitmproxy` re-signing TLS with a root it generates on first boot,
`squid` demanding Basic authentication, `dnsmasq` answering split-horizon, and
an `nginx` that will not tunnel a `CONNECT`. Everything else in this repo
judges a certificate chain somebody recorded; this judges one a real proxy is
really re-signing, one hop away.

![portcall bringing the hostile network up, running a check inside it, and
exiting 2 with the planted blockers named](demo/portcall-demo.gif)

One command does all of that:

```bash
npm run demo
```

It brings the network up, runs a real `portcall check` inside it, prints the
report and tears the network down - and it *requires* the check to exit `2`
([ADR-0046](docs/adr/0046-the-demo-is-a-real-check-that-must-exit-2.md)). A run
of this network that finds nothing is a broken demo, not a passing one, so the
demo is an assertion and CI runs it as one. It needs Docker with `compose` v2,
plus the Node that runs the script - no `npm ci`, no build, no toolchain. SPEC.md §11 asked for
one command "on a machine with nothing installed"; that was never accurate of
this demo, since the demo *is* five containers, and ADR-0047 amends it.

The GIF is committed by hand from a render the CI `demo` job produced, and it
lands with the first green one - until then the link above is dead. It
is not regenerated per commit, and CI does not diff it - frame timing depends
on how long Docker took on that runner, so a diff would flake on every run and
teach everyone to ignore it
([ADR-0047](docs/adr/0047-the-demo-recording-is-a-tape-rendered-in-ci.md)). It
can therefore lag the current output. The command above is what runs on every
push; the image is only a picture of it.

```sh
docker compose -f test/harness/docker-compose.yml up --wait
docker compose -f test/harness/docker-compose.yml build portcall
docker compose -f test/harness/docker-compose.yml run --rm portcall
docker compose -f test/harness/docker-compose.yml down -v
```

`build` is not optional: the image bakes the repo with `COPY . .` and nothing is
bind-mounted, so a `run` after an edit re-executes the tree as it stood at the
last build.

The third command is what runs the suite — `npm run test:integration`, inside
the network, where the harness's own resolver and names apply. Run on the host
instead, that script refuses immediately and prints the three commands above.

It is opt-in on purpose, and it is not part of `npm test` or `npm run verify`
([ADR-0025](docs/adr/0025-the-hostile-network-harness-is-a-real-network-run-outside-verify.md)):
portcall's whole premise is that it runs on a locked-down machine where nothing
is installed, and a default suite needing Docker would skip on exactly those
machines. Requires Docker with `compose` v2. CI runs it as its own Linux-only
job: the hosted Windows and macOS runners have no Linux Docker daemon, and
nothing about a proxy re-signing TLS is host-OS dependent.

The harness has been run. Its seven tests — covering all five planted
conditions — pass on a development machine's Docker daemon, both against a warm network
and from a cold `down -v` start that regenerates `mitmproxy`'s root, so the ids
and severities it asserts against a live `mitmproxy`, `squid`, `dnsmasq` and
`nginx` are observed rather than only written down. It has since also passed on a
hosted runner: the CI `harness` job executes the same compose file on every
push, and it went green on `c06c8c4` alongside the other six jobs — `verify` on
all three OSes, `node-compat` on 22 and 24, and `binaries`. That is one green
run on one runner, not a claim about every runner.

[test/harness/README.md](test/harness/README.md) has the per-service table of
which condition each one plants and which finding it provokes, the fixed
addresses, how to debug a failing scenario, how the certificates are
generated, and the limitations of the stand-ins, stated rather than hidden.

## Why it is built this way

Every non-obvious decision has an ADR in [docs/adr/](docs/adr/) — the context,
the choice, the alternatives that lost, and why. Start with
[ADR-0004](docs/adr/0004-read-only-and-credential-free-enforced-by-guardrail-tests.md)
if what you want to know is whether the trust properties above are enforced or
merely claimed.

For the TLS work specifically:
[ADR-0021](docs/adr/0021-peculiar-x509-lands-scoped-to-parsing-not-trust.md)
takes the one new runtime dependency and scopes it to parsing, never to trust;
[ADR-0022](docs/adr/0022-distinguished-names-are-a-redacted-evidence-kind.md)
makes a certificate's distinguished name its own evidence kind so it is hashed
like every other customer-owned string;
[ADR-0023](docs/adr/0023-tls-probe-discovers-its-proxy-from-environment-variables-only.md)
is the deliberately narrow proxy discovery described above;
[ADR-0024](docs/adr/0024-tls-chain-outcome-carries-a-tunnel-phase.md) gives a
failed capture a `tunnel` phase of its own, so "the proxy answered instead of
tunnelling" never gets filed as a connect failure; and
[ADR-0025](docs/adr/0025-the-hostile-network-harness-is-a-real-network-run-outside-verify.md)
is why the hostile network is opt-in.

## License

Apache-2.0. See [LICENSE](LICENSE).
