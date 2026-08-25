# Portcall — working agreement

Read `SPEC.md` first. It is the brief; this file is how to work on it.

## What this project is for

Portcall is a portfolio-critical build. It exists to demonstrate that its author does
forward-deployed engineering — arriving in an environment he does not own and making software
work there. Every decision should be legible to a hiring manager reading the repo cold. That
means the *reasoning* is part of the deliverable, not overhead.

## Milestone discipline

- Work one milestone at a time, M0 → M5, in the order given in SPEC.md §8.
- A milestone is done when its exit criteria pass **and** CI is green on all three OSes.
- Do not start the next milestone with the previous one red or partially landed.
- Never mark a milestone complete with skipped tests, a TODO in a code path, or a check that
  emits a finding with no `remediation`.

## Architecture decision records

Every non-obvious decision gets an ADR in `docs/adr/NNNN-title.md`, numbered sequentially,
following the format already used in `dz3ka/bosun` and `dz3ka/tollgate`.

Write the ADR when the decision is made, not retroactively at the end of a milestone. An ADR
states the context, the decision, the alternatives that were rejected, and *why* — including
the ones that were rejected for boring reasons like "this runs on a customer's laptop".

SPEC.md §9 lists six decisions that already need writing up as ADRs 0001–0006 during M0.

## Non-negotiables

These come from SPEC.md §4 and are not to be relaxed for convenience:

- No writes outside the working directory. No installs. No config mutation.
- No reading credentials, keychains, tokens, private keys or browser profiles. No prompting
  for a password. The proxy probe reports the auth scheme demanded; it never authenticates.
- No network calls except to hosts named in the active profile.
- No telemetry. No analytics. No "anonymous usage" anything.
- Redaction is on by default and applied at the report boundary, not per call site.

If a check seems to require breaking one of these, the check is out of scope — say so rather
than working around it.

## Code conventions

- TypeScript, strict mode, no `any` in committed code.
- Probes are pure: `(profile, environment) => Finding[]`. I/O lives at the edges so the
  evaluation logic is fixture-testable.
- Write the `remediation` string before writing the check. A finding a reader cannot act on
  is not worth emitting.
- Finding `id`s are stable and greppable (`tls.intercepted`, `truststore.node.missing-root`).
  Once public, treat them as API.
- Errors carry the distinction that matters operationally: DNS vs connect-refused vs timeout
  vs TLS vs HTTP are four different teams and four different tickets. Never collapse them.

## Testing

- Every parser is fixture-driven; commit the fixtures.
- The `docker compose` hostile-network harness (SPEC.md §10) is a first-class deliverable, not
  a test util. Build it during M3 and keep it green.
- Cross-OS CI from M0. The trust-store probe behaves differently on each platform and that
  difference is the point of the project.

## Public from the start

The repo is public from M0. Commits, ADRs and milestone boundaries are all readable. Write
commit messages that explain *why*, in the style already used in `dz3ka/bosun`.

The README says plainly what the tool does not do (SPEC.md §3) and that binaries are unsigned
until v2. Understating is fine; overstating is not.
