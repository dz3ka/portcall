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

> Note: there is no ADR-0035, and nothing is missing. The number was allocated
> during M4 and never used; it is cited nowhere in the tree. The sequence skips
> it deliberately rather than renumbering, because 0036 onwards are already
> cited from `src/` and 0038–0040 are already public in the history — moving a
> number would point every one of those citations at the wrong document.

> Note: ADR-0039's `Status:` line records that ADR-0037 was cited from `src/`
> but "not yet written up in this directory". That was true on the day 0039 was
> accepted and is no longer true: 0033, 0034, 0036 and 0037 were written up
> during M4 from their own commits and the code that cites them, and every
> `ADR-NNNN` occurrence in the tree now resolves to a file here. 0039 is left
> exactly as written, because an Accepted ADR is immutable and its disclaimer is
> an honest record of what the directory held at the time - read that line as
> history, not as the directory's current state.

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
| [0033](0033-the-os-trust-store-is-read-through-a-pinned-argv-table.md) | The OS trust store is read through a pinned argv table, not a banned word | Accepted |
| [0034](0034-the-tls-probe-hands-the-anchor-it-observed-to-the-run.md) | The `tls` probe hands the anchor it observed to the rest of the run | Accepted |
| [0036](0036-java-keystores-are-parsed-in-process-and-never-unlocked.md) | Java keystores are parsed in-process, and portcall never supplies a password | Accepted |
| [0037](0037-each-trust-store-gets-its-own-slice-of-the-runs-remaining-time.md) | Each trust store gets its own slice of the run's remaining time | Accepted |
| [0038](0038-correlated-anchors-take-evidence-priority-in-missing-root-truncation.md) | Correlated anchors take evidence priority over alphabetical order in truststore missing-root findings | Accepted |
| [0039](0039-the-windows-machine-root-budget-is-set-from-a-563-root-host.md) | The `windows-machine-root` read budget is set from a 563-root host, not a 41-root laptop | Accepted |
| [0040](0040-the-trust-store-reader-hands-powershell-a-null-module-analysis-cache-path.md) | The trust-store reader hands PowerShell a null module-analysis cache path | Accepted |
| [0041](0041-the-harness-plants-its-os-trust-store-at-container-start.md) | The harness plants its OS trust store at container start, and stays a Node-only profile | Accepted |
| [0042](0042-the-injection-proof-asserts-membership-by-re-derivation.md) | The injection proof asserts membership by re-derivation, and its teeth sit in two requirements | Accepted |
| [0043](0043-a-profile-filename-is-public-cli-surface.md) | The named profiles are Claude Code and Cursor, and a profile filename is public CLI surface | Accepted |
| [0044](0044-profiles-check-proves-freshness-not-validity.md) | `profiles:check` proves the embed is fresh, not that a profile is valid | Accepted |
| [0045](0045-the-self-contained-html-claim-is-a-static-enumeration.md) | The self-contained HTML claim is a static enumeration, not a rendered load | Accepted |
| [0046](0046-the-demo-is-a-real-check-that-must-exit-2.md) | The demo is a real check against the harness, and it must exit 2 | Accepted |
| [0047](0047-the-demo-recording-is-a-tape-rendered-in-ci.md) | The demo recording is a tape rendered in CI, and the committed GIF is a snapshot | Accepted |
| [0048](0048-release-checksums-are-signed-with-sigstore-keyless.md) | Release checksums are signed with Sigstore keyless; the binaries stay unsigned until v2 | Accepted |
| [0049](0049-shell-heredocs-are-not-a-file-writing-primitive-on-windows.md) | Shell heredocs are not a file-writing primitive on this Windows toolchain | Accepted |
