# Portcall

One command a forward-deployed engineer hands to a prospective customer's
platform or security team *before* a deployment. It runs inside their network,
on their machine, and answers a single question:

> Will this AI developer tool actually work here — and if not, exactly what is
> blocking it and what has to change?

It is not a diagnostic you run after the deployment fails. It is the artifact
you send ahead of the first call.

**Status:** M0 skeleton. The CLI, profile loader, finding model, three report
renderers and the redaction boundary exist. Probes (DNS, egress, proxy, TLS,
trust-store) are not registered yet. Binaries are unsigned until v2.

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

The proxy probe, when it exists, will report the auth scheme demanded. It will
never authenticate.

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
