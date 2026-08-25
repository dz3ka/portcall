# Portcall — enterprise deployment readiness checker

**Status:** scoped, not started. This document is the build brief.
**Owner:** Bogdan Džekić (dzeka)
**Repo:** `github.com/dz3ka/portcall` (to be created, public from M0)

---

## 1. What this is

One command a forward-deployed engineer hands to a prospective customer's platform or
security team before a deployment. It runs inside their network, on their machine, and
answers a single question:

> Will this AI developer tool actually work here — and if not, exactly what is blocking it
> and what has to change?

It is not a diagnostic you run after the deployment fails. It is the artifact you send
*ahead* of the first call, so the call is about the three real blockers instead of an hour
of "can you try it now?"

## 2. Why it exists

Every enterprise rollout of a developer tool dies in the same four places, and none of them
are the product:

1. **Egress.** The endpoints the tool needs are not reachable, or are reachable only through
   a proxy nobody documented.
2. **TLS interception.** A corporate middlebox re-signs every connection with a private root.
   The tool's HTTP client rejects it and reports something useless like `self-signed
   certificate in certificate chain`.
3. **Trust stores.** The corporate root *is* installed — in the OS store. Node doesn't read
   the OS store the way people assume, Python reads `certifi`, Java reads its own `cacerts`,
   Go has its own rules. The tool fails on a machine where the browser works fine, which is
   the single most confusing failure mode in this entire category.
4. **Proxy behaviour.** PAC file, WPAD, `NO_PROXY` written wrong, or a proxy that demands
   NTLM/Kerberos the tool's client can't speak.

An FDE learns all four in their first month and then re-diagnoses them by hand at every
customer. Portcall is that diagnosis, written down and made runnable.

## 3. Non-goals for v1

Say no loudly, in the README, so the scope reads as a decision rather than an omission.

- **Not a security scanner.** It does not assess the customer's posture. It tests whether
  *our* software can run. Different tool, different trust conversation.
- **No SSO / OIDC round trip.** v2.
- **No EDR, code-signing or endpoint-policy checks.** v2.
- **No streaming / WebSocket longevity checks.** v2 — this matters a lot for AI tools
  (proxies buffer SSE and kill idle sockets) and deserves its own milestone.
- **Not a general network troubleshooter.** Everything it reports is anchored to a profile.

## 4. Trust properties — these *are* the product

A security team that cannot satisfy itself in ten minutes that running this is safe will not
run it, and then nothing else in this document matters. These are hard constraints, tested
in CI, and stated at the top of the README.

1. **Read-only.** No writes outside the working directory. No configuration changes, no
   installs, no registry or keychain writes.
2. **No credentials.** It never reads keychains, tokens, private keys, or browser profiles,
   and never prompts for a password.
3. **No telemetry, ever.** Nothing leaves the machine. The operator sends the report or
   nobody does.
4. **Redacted by default.** Internal hostnames, usernames, IPs and serial numbers are hashed
   in the emitted report. `--no-redact` exists for internal use and prints a warning.
5. **Auditable.** Single binary, public source, reproducible build, and every check has a
   documented rationale and remediation.

A CI test asserts (1) by running the binary under a filesystem watcher and failing on any
write outside `cwd`.

## 5. Distribution

The tool exists because enterprise machines are locked down. Requiring `npm install` from a
vendor would be self-refuting.

- **Release artifact:** one self-contained executable per platform —
  `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win-x64`.
  Built with `bun build --compile --target=...`, cross-compiled from CI on one runner.
- **Secondary path:** the source stays Node-compatible so `npx portcall` works for anyone who
  prefers it. Node compatibility is a CI matrix job, not an afterthought.
- **Verification:** every release ships SHA-256 sums and a reproducible-build note. Signing
  (Developer ID / Authenticode) is tracked as a v2 item — until then the README says plainly
  that binaries are unsigned and tells the reader how to build from source instead.

## 6. Architecture

```
portcall
├─ cli/            argument parsing, exit codes, human output
├─ engine/         probe scheduler, global timeout budget, severity roll-up
├─ profiles/       YAML — what a given tool requires. Data, not code.
├─ probes/
│   ├─ dns/        resolution, split-horizon detection, DoH reachability
│   ├─ egress/     TCP connect + HTTP reachability per required endpoint
│   ├─ proxy/      env vars, PAC/WPAD discovery, CONNECT support, auth scheme
│   ├─ tls/        chain capture, interception detection, root identification
│   └─ truststore/ OS store + Node / Python / Java / Go stores
├─ redact/         default-on redaction applied at the report boundary
└─ report/         json (canonical) · html (single self-contained file) · text
```

Every probe is a pure function of `(profile, environment) -> Finding[]`. Nothing mutates
global state. That is what makes the whole thing testable against fixtures.

### The finding model

```ts
type Severity = 'blocker' | 'degraded' | 'ok' | 'unknown';

interface Finding {
  id: string;              // stable and greppable, e.g. 'tls.intercepted'
  probe: string;
  severity: Severity;
  title: string;
  evidence: Evidence[];    // what was observed; redacted at the boundary
  remediation?: string;    // what to change — the reason anyone runs this
  docs?: string;           // link to the explanation in the repo
}
```

`remediation` is not optional in spirit. A finding that says "TLS interception detected" and
stops is a worse version of the error message the user already had. The value is
*"a middlebox is re-signing your traffic with `CN=Acme Corp Proxy CA`. Node does not read the
macOS system keychain; set `NODE_EXTRA_CA_CERTS=/path/to/acme-root.pem` or run with
`--use-openssl-ca`."*

Write the remediation first. If you cannot write one, the check is not worth shipping.

### Profiles are data

```yaml
# profiles/generic-ai-tool.yaml
name: Generic AI developer tool
endpoints:
  - host: api.anthropic.com
    port: 443
    purpose: model inference
    required: true
    expect_streaming: true
  - host: registry.npmjs.org
    port: 443
    purpose: extension updates
    required: false
runtimes: [node]           # which trust stores to cross-check
tls:
  min_version: "1.2"
  interception_tolerated: true   # some tools work fine behind a re-signing proxy
```

Adding a vendor is a PR against `profiles/`, not a release. Ship three at M5: a generic AI
tool, and two named ones from your target five (their required endpoints are public).

## 7. Probes — v1 scope

**`dns`** — resolve every profile host; report NXDOMAIN, split-horizon answers (public host
resolving to RFC1918), unusually long resolution, and whether DoH is blocked.

**`egress`** — TCP connect and an HTTP request per endpoint, direct and (if one exists) via
the discovered proxy. Distinguish *DNS fails* / *connect refused* / *connect times out* /
*TLS fails* / *HTTP error*, because those are four different tickets for four different teams.

**`proxy`** — read `HTTP(S)_PROXY`, `NO_PROXY`, platform proxy settings; discover PAC via
`WPAD` and explicit config; evaluate the PAC against each profile host; test whether the
proxy supports `CONNECT` to the required ports; report the auth scheme it demands
(Basic / NTLM / Negotiate) without ever attempting to authenticate. Validate `NO_PROXY`
syntax — silent `NO_PROXY` mistakes are a top-three cause of "works for me".

**`tls`** — connect with verification *disabled* (deliberately, to observe rather than
validate), capture the presented chain, then evaluate it in-process:
- Is the chain's root a public CA or a private one? → interception detected, and *who*.
- Negotiated protocol version and cipher.
- Chain depth, expiry, and whether the leaf matches the SNI.
- Whether the same host presents a *different* chain via the proxy than direct.

**`truststore`** — the differentiator. Locate and read:
- OS store (macOS keychain, Windows cert store, Linux `ca-certificates`),
- Node (`NODE_EXTRA_CA_CERTS`, bundled roots, `--use-openssl-ca` behaviour),
- Python (`certifi` location, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`),
- Java (`cacerts` for each JDK found),
- Go (`SSL_CERT_FILE` / `SSL_CERT_DIR`).

Then cross-reference: *the root observed intercepting traffic in the `tls` probe — is it
present in each store the profile's runtimes actually read?* That single cross-check is the
answer to the most common enterprise deployment failure in this category, and almost nothing
public does it.

## 8. Milestones

Same discipline as Bosun and Tollgate: each milestone lands green, with ADRs, before the next
one starts.

| # | Scope | Exit criteria |
|---|---|---|
| **M0** | Skeleton: CLI, profile loader, finding model, three report renderers, CI, cross-platform binary build | `portcall check --profile generic` runs, emits an empty-but-valid report, binaries build for all five targets in CI |
| **M1** | `dns` + `egress` | Real findings against a live profile; fixture tests for every failure class |
| **M2** | `proxy` | PAC evaluation tested against fixture PAC files; auth scheme detected without authenticating |
| **M3** | `tls` | Chain capture and interception detection, verified against a real MITM proxy in the test harness |
| **M4** | `truststore` + the cross-check | Corporate-root-missing-from-Node correctly identified on all three OSes in CI |
| **M5** | Public release | HTML report, README, one-command demo recording, three shipped profiles, signed checksums |

M0–M5 is the publishable unit. v2 (SSO round trip, streaming survival, endpoint policy) is a
separate arc and should not delay going public.

## 9. Decisions to record as ADRs

1. **TypeScript compiled to a self-contained binary.** Chosen over Go despite Go being the
   faster path, because TypeScript is the ecosystem of the tools this targets and the
   distribution problem is solvable with `bun build --compile`. The constraint that drove it:
   a customer's security team will not run a package manager for a vendor.
2. **Capture with `node:tls`, validate with `@peculiar/x509`.** The handshake needs a real TLS
   client; the *evaluation* must be pure and fixture-testable, and must not depend on which
   runtime is executing. Keeping them separate also means the validation logic is identical
   under Bun and Node.
3. **Profiles are data.** A new vendor is a PR, not a release.
4. **Read-only and credential-free, enforced in CI.** See §4.
5. **Redaction at the report boundary, on by default.** The JSON that leaves the customer's
   network must be safe to email to a vendor without a legal review.
6. **Deterministic exit codes** (`0` ok, `1` degraded, `2` blocker, `3` tool error) so the
   customer can run it in their own CI.

## 10. Testing

- **Unit** — PAC evaluation, `NO_PROXY` matching, certificate chain parsing, trust-store
  parsers. All fixture-driven.
- **Fixtures** — recorded certificate chains (public, intercepted, expired, wrong-SNI), real
  PAC files, trust-store dumps from all three OSes.
- **Integration harness** — `docker compose` bringing up a deliberately hostile network:
  `mitmproxy` re-signing with a generated root, `squid` requiring Basic auth, a DNS server
  answering split-horizon, and an nginx that refuses `CONNECT` on non-443. The suite asserts
  Portcall correctly identifies each condition. **This harness is the most persuasive thing in
  the repo** — it is the proof you understand the failure modes, not just the checks.
- **Cross-OS CI** — macOS, Windows and Linux runners, because the trust-store probe is
  meaningfully different on each and that is the whole point.

## 11. Demo

Follow the pattern that already works in your repos: one command, on a machine with nothing
installed, that brings up the hostile-network harness, runs Portcall against it, and shows the
report identifying every planted blocker — recorded as a short screen capture for the site.

## 12. Naming

`portcall` — a ship's visit to a port: you arrive somewhere you don't own, and the first thing
you do is find out what you're allowed to do there. It also sits naturally beside **Bosun**,
and "port" is the obvious pun. Alternatives if it's taken on npm: `readyz`, `preflight`,
`landfall`.
