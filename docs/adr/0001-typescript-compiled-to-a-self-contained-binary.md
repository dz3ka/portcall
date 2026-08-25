# ADR-0001: TypeScript compiled to a self-contained binary, not Go

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

Portcall runs on a machine nobody on this side owns, inside a network that is
locked down on purpose. That makes distribution the first constraint rather
than a packaging detail at the end (SPEC.md §5): a customer's security team
will not run a package manager for a vendor in order to evaluate whether the
vendor's software is safe to run. Whatever the tool is written in, it has to
arrive as one file they can hash, read the source of, and execute.

Go is the shorter path to that file and is the default answer for this shape of
tool. Two things pull the other way. The tools portcall clears the way for are
Node/TypeScript tools, so the profiles, the endpoint expectations and the
failure modes are all described in that ecosystem's terms. More importantly the
differentiating probe — the trust-store cross-check (SPEC.md §7) — is a
statement about how *Node* resolves roots compared to the OS store, `certifi`,
`cacerts` and Go's own rules. Written in Go, that reasoning is re-derived from
documentation about a runtime the tool never executes.

## Decision

Source is TypeScript in strict mode, Node-compatible (`engines.node >=22.6`,
run directly from `src/` in development via Node's type stripping). The release
artifact is one self-contained executable per platform, built with
`bun build --compile --target=...` and cross-compiled from CI on one runner for
`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64` and `win-x64`.

`npx portcall` stays a supported secondary path for anyone who prefers it, and
Node compatibility is a CI matrix job rather than an assumption. Runtime
dependencies are kept to the minimum the job needs — `yaml` and `zod` at M0 —
because every one of them is a line in someone's review.

## Alternatives considered

- **Go.** Rejected: it wins on binary size, startup and cross-compilation, and
  loses on the only probe that makes this project worth publishing. Reading
  `NODE_EXTRA_CA_CERTS` semantics, bundled-root behaviour and `--use-openssl-ca`
  from the outside is exactly the second-hand knowledge the tool exists to
  replace with an observation.
- **Rust.** Rejected: the best artifact and the longest road to M5, with the
  same ecosystem mismatch as Go and none of Go's speed of authorship.
- **Python with PyInstaller.** Rejected: large, slow-starting bundles, and
  packer stubs are the single most reliable way to get quarantined by EDR on a
  locked-down Windows laptop. A readiness checker that trips the controls it is
  meant to describe has a bad first five minutes.
- **Ship as an npm package only.** Rejected for the boring reason: this runs on
  a customer's laptop, and asking their security team to `npm install` from the
  vendor to find out whether the vendor is safe is self-refuting. It is also
  fragile in precisely the environments portcall targets, where the npm
  registry is often the proxied or blocked endpoint being diagnosed.
- **Node's single-executable applications (SEA).** Rejected: still experimental,
  needs a per-platform post-processing step and a signing step to run at all on
  macOS, and would put an unstable build path on the critical route to M0's exit
  criteria. `bun build --compile` does the same job today.

## Consequences

Two runtimes have to stay green, Node and Bun. That cost is contained by
keeping the source dependency-light and by ADR-0002's rule that evaluation logic
never touches a runtime-specific object; the Node matrix job is what proves it.
Bun is a build-time dependency only — nothing on the customer's machine needs it.

Binaries are unsigned until v2, so the README states that plainly and tells the
reader how to build from source instead. That is a disclosure, not a mitigation.

Re-open if `bun build --compile` drops one of the five targets, or if a probe
turns out to need a native module — a native dependency would break the
cross-compile-from-one-runner property that makes this decision cheap.
