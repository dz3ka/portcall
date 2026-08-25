# ADR-0003: Profiles are data, embedded at build time

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

What a given AI developer tool requires — hosts, ports, purpose, which runtimes'
trust stores matter, whether TLS interception is tolerated — is public
information that changes on the vendor's schedule, not on ours. If a profile is
code, then adding a vendor is a code review and a release, and an FDE sitting in
a customer's office who needs one more endpoint checked this afternoon cannot
have it. The design intent (SPEC.md §6) is the opposite: adding a vendor is a PR
against `profiles/`.

A second force comes from ADR-0001. The release artifact is one self-contained
executable, so a built-in profile cannot be read from a `profiles/` directory
next to the binary. There is no directory next to the binary.

## Decision

Profiles are YAML files in `profiles/`, validated by a strict `zod` schema
(`src/profiles/schema.ts`). `scripts/embed-profiles.mjs` generates
`src/profiles/builtin.generated.ts` containing the YAML **text** of each
built-in profile, and `npm run profiles:check` fails the build if that generated
file is stale.

Because what is embedded is text, `parseProfile` is one code path for a built-in
profile and for `--profile ./acme.yaml`. The customer-supplied path is the one
that must never surprise anyone, so it is the path exercised every time the tool
runs at all.

The schema is `.strict()`: an unknown key is a load error, and so are a
malformed hostname, an out-of-range port, and duplicate endpoints.

## Alternatives considered

- **Profiles as TypeScript modules.** Rejected: typing comes free, but the
  profile becomes code, contributing one requires knowing the codebase, and —
  the part that matters — every profile would then be able to execute inside the
  customer's network. A security team reading the source to rule that out is
  exactly the reader this repo is written for.
- **Embed parsed objects instead of YAML text.** Rejected: it produces two
  loaders, one for embedded objects and one for files, and the schema then
  guards only one of them. The unguarded one would be the customer's.
- **Fetch profiles from a URL at run time.** Rejected for the boring reason:
  this runs inside a network that may well be blocking us, so it would fail in
  the exact conditions where it is needed. It also contradicts trust property 3
  — a tool that phones home for config costs the security team a conversation,
  regardless of what the payload contains.
- **A lenient schema that ignores unknown keys.** Rejected: a typo in
  `endpoints:` would silently drop the endpoint the customer cared about most,
  and the report would then say "no blockers". That is the worst output this
  tool can produce, and it would be produced confidently.
- **Generate the embedded file at install time rather than committing it.**
  Rejected: the shipping artifact has no install step, and a generated file that
  is absent from the tree cannot be reviewed in the PR that changes it.

## Consequences

Adding a vendor is a PR touching `profiles/*.yaml` plus a regenerated file, with
no logic to review. The reviewer checks whether the endpoints are true, which is
the only question worth their time.

The committed generated file can drift from its source. That is what
`profiles:check` guards, and it is the first step of both `npm run verify` and
`npm run build` rather than a separate discipline anyone has to remember.

Profiles cannot express conditions — "this endpoint only if the customer uses
feature X" is unrepresentable. That is deliberate: the moment a profile grows an
`if`, it is code again and this ADR is void. Re-open there, and not before.
