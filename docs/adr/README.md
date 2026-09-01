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

> Note: ADR-0002 was written in M0, ahead of the code it governs, because it
> constrains the finding model and the fixture format that M0 ships. Its
> dependency landed in M3: `src/probes/tls/evaluate.ts` and
> `src/probes/tls/public-roots.ts` are that decision in the tree.

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
| [0010](0010-pac-evaluation-via-node-vm-zero-new-dependency.md) | PAC evaluation via `node:vm`, zero new dependency | Accepted |
| [0011](0011-pac-sandbox-hardening-defends-a-distinct-attack-per-item.md) | PAC sandbox hardening, one item per distinct attack | Superseded by ADR-0018 |
| [0012](0012-pac-helpers-resolve-only-the-pre-resolved-target-host.md) | PAC helpers resolve only the pre-resolved target host | Accepted |
| [0013](0013-auth-scheme-classification-cannot-construct-a-credential-header.md) | Auth-scheme classification cannot construct a credential header | Accepted |
| [0014](0014-profile-schema-gains-proxy-pac-url.md) | Profile schema gains one optional field, `proxy.pac_url` | Accepted |
| [0015](0015-os-native-proxy-settings-are-a-v1-non-goal.md) | Reading OS-native/platform proxy settings is a v1 non-goal | Accepted |
| [0016](0016-wpad-discovery-is-dns-based-only-not-dhcp-option-252.md) | WPAD discovery is DNS-based only, not DHCP option 252 | Accepted |
| [0017](0017-pac-evaluation-runs-on-a-terminable-worker-thread.md) | PAC evaluation runs on a terminable Worker thread | Accepted |
| [0018](0018-pac-confinement-is-a-fresh-realm-not-a-hardened-host-object.md) | PAC confinement is a fresh realm, not a hardened host object | Accepted |
| [0019](0019-pac-worker-self-exits-before-its-own-pending-microtasks-run.md) | The PAC worker self-exits before its own pending microtasks run | Accepted |
| [0020](0020-context-budget-guard-covers-multi-work-package-fix-rounds.md) | Context-budget guard's example set now covers multi-work-package fix rounds | Accepted |
| [0021](0021-peculiar-x509-lands-scoped-to-parsing-not-trust.md) | `@peculiar/x509` lands, scoped to parsing and never to trust | Accepted |
| [0022](0022-distinguished-names-are-a-redacted-evidence-kind.md) | Distinguished names are their own evidence kind, and they are redacted | Accepted |
| [0023](0023-tls-probe-discovers-its-proxy-from-environment-variables-only.md) | The `tls` probe discovers its proxy from environment variables only | Accepted |
| [0024](0024-tls-chain-outcome-carries-a-tunnel-phase.md) | `TlsChainOutcome` carries a `tunnel` phase of its own | Accepted |
| [0025](0025-the-hostile-network-harness-is-a-real-network-run-outside-verify.md) | The hostile-network harness is a real network, and it runs outside `verify` | Accepted |
| [0026](0026-a-bundled-root-counts-only-on-the-leafs-issuance-path.md) | A bundled root counts only on the leaf's issuance path | Accepted |
| [0027](0027-a-timed-out-capture-is-its-own-finding-not-a-coded-failure-with-no-code.md) | A capture that timed out is its own finding, not a coded failure with no code | Accepted |
| [0028](0028-the-tls-probe-is-silent-on-ports-other-than-443.md) | The `tls` probe's silence on other ports is deliberate | Accepted |
| [0029](0029-interception-severity-is-decided-once-in-the-trust-verdict.md) | Interception severity is decided once, in the trust verdict | Accepted |
| [0030](0030-the-harness-zone-is-ipv4-only-and-aaaa-is-unanswered.md) | The harness zone is IPv4-only, and AAAA is left unanswered | Accepted |
| [0031](0031-cross-runtime-parity-is-a-verdict-claim-not-a-bundle-claim.md) | Cross-runtime parity is a verdict claim, not a bundle claim | Accepted |
| [0032](0032-per-store-os-unreadable-not-one-aggregate.md) | An unreadable OS store gets its own finding, not a shared aggregate | Accepted |
| [0038](0038-correlated-anchors-take-evidence-priority-in-missing-root-truncation.md) | Correlated anchors take evidence priority over alphabetical order in truststore missing-root findings | Accepted |
| [0039](0039-the-windows-machine-root-budget-is-set-from-a-563-root-host.md) | The `windows-machine-root` read budget is set from a 563-root host, not a 41-root laptop | Accepted |
