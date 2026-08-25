# Architecture Decision Records

Each ADR captures one decision a competent reviewer would ask "why?" about:
the context, the choice, the alternatives weighed, and the consequences. ADRs
are immutable once accepted — to change a decision, add a new ADR that
**supersedes** the old one (and mark the old one Superseded).

Numbering is sequential at creation (`NNNN-kebab-title.md`). Status is one of:
`Proposed` · `Accepted` · `Superseded by ADR-XXXX` · `Deprecated`.

> Note: `SPEC.md` §9 names six decisions that had to be written up during M0.
> They are ADRs 0001–0006 below, in the order the spec lists them, and the
> source cites them by number (`src/cli/exit-codes.ts` → ADR-0006,
> `src/redact/index.ts` → ADR-0005, `src/profiles/schema.ts` → ADR-0003).
> Decisions after 0006 take their numbers at the milestone whose code forces
> them, not before.

> Note: ADR-0002 records a decision whose dependency does not land until M3.
> It is written now because it constrains the finding model and the fixture
> format that M0 ships; it describes an intended shape, not code in the tree.

## Template

```markdown
# ADR-NNNN: <title>

- **Status:** Accepted
- **Date:** YYYY-MM-DD
- **Deciders:** <who>

## Context
<the forces at play: requirements, constraints, what makes this non-obvious>

## Decision
<the choice, stated plainly>

## Alternatives considered
<each rejected option and why it lost — including the boring reasons>

## Consequences
<what becomes easier, what becomes harder, follow-ups triggered>
```

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-typescript-compiled-to-a-self-contained-binary.md) | TypeScript compiled to a self-contained binary, not Go | Accepted |
| [0002](0002-capture-with-node-tls-validate-with-peculiar-x509.md) | Capture with `node:tls`, validate with `@peculiar/x509` | Accepted |
| [0003](0003-profiles-are-data-embedded-at-build-time.md) | Profiles are data, embedded at build time | Accepted |
| [0004](0004-read-only-and-credential-free-enforced-by-guardrail-tests.md) | Read-only and credential-free, enforced by guardrail tests | Accepted |
| [0005](0005-redaction-is-a-typed-boundary-on-by-default.md) | Redaction is a typed boundary, on by default | Accepted |
| [0006](0006-deterministic-exit-codes-with-unknown-as-degraded.md) | Deterministic exit codes, with `unknown` as degraded | Accepted |
| [0007](0007-doh-reachability-is-profile-declared.md) | DoH reachability is profile-declared, never resolver-chosen | Accepted |
| [0008](0008-port-derived-targets-closed-class-union-data-returning-seam.md) | Port-derived targets, closed failure classes, a data seam | Accepted |
| [0009](0009-probe-error-evidence-is-a-closed-class-and-a-machine-code.md) | Probe errors carry a closed class and a code, never the message | Accepted |
