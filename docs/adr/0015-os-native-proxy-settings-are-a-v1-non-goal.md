# ADR-0015: Reading OS-native/platform proxy settings is a v1 non-goal

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

SPEC.md §7 lists platform proxy settings — Windows's WinINET/registry proxy
configuration, macOS's `scutil --proxy` / System Configuration framework,
GNOME/KDE's own proxy stores on Linux — alongside `HTTP_PROXY`/`HTTPS_PROXY`
environment variables as sources the `proxy` probe should consider. On many
managed enterprise Windows and macOS machines, the platform setting is the
*only* place a proxy is actually configured — IT pushes it via GPO or an MDM
profile, and no environment variable is ever set — so a probe that reads only
env vars will under-report "no proxy configured" on exactly the fleet this
tool is built to be run on ahead of a deployment.

Reading it properly is real, OS-specific surface, though. Each platform stores
this differently, none of it is exposed by a Node builtin, and getting it
right means either shelling out to a platform tool (`netsh`, `scutil`, a
registry read) or a native binding — both cross-platform-fragile and both new
surface a security team has to reason about, on a project whose ADR-0001
already commits to a single-runner cross-compile with no native dependencies.

## Decision

v1 reads `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables only.
Platform/OS-native proxy settings reading is explicitly out of scope for M2 —
not silently absent, a stated non-goal recorded here so a reader of the README
or this ADR knows the gap exists rather than assuming portcall found "no
proxy" because there truly is none.

This does not remove PAC/WPAD discovery from scope: WPAD (ADR-0016) is
platform-independent — a DNS lookup and an HTTP fetch, both already inside
this project's existing I/O seam — so a network that publishes its proxy via
WPAD or an explicit `proxy.pac_url` (ADR-0014) is still fully covered by v1.
The gap is specifically the case where a proxy is set *only* in the OS's own
settings store, with no env var and no PAC/WPAD path.

## Alternatives considered

- **Shell out to a platform command (`netsh winhttp show proxy`, `scutil
  --proxy`, a `gsettings` read).** Rejected for the boring reason CLAUDE.md
  names directly: this runs on a customer's laptop under whatever runtime and
  permissions they gave it, and a tool whose whole pitch is a short, auditable
  list of things it does now has to reason about spawning a subprocess per
  platform, each with its own failure modes (missing binary, unexpected output
  format across OS versions) that would need cross-platform CI coverage this
  project does not yet have for that surface.
- **A native Node addon or platform-specific npm package
  (`win-proxy`-style) per OS.** Rejected: three new dependencies (one per
  platform) for one probe, each a compiled native module — directly against
  ADR-0001's single cross-compiled binary and ADR-0002's precedent that a new
  dependency needs to earn its place; a WebCrypto-based pure-JS library
  cleared that bar for the `tls` probe, three native platform bindings would
  not.
- **Read the registry/plist/gsettings files directly.** Rejected: the format
  and location of each is undocumented-enough to be a moving target across OS
  versions, and getting it wrong silently (a plist schema change) produces a
  confidently wrong "no proxy" finding, which is worse than the honest gap
  this ADR records.

## Consequences

On a network where a proxy is configured only via OS-native settings, with no
env var and no PAC/WPAD path, the `proxy` probe reports `proxy.none-configured`
even though a proxy is genuinely in effect — a known, documented false
negative for that one configuration shape, not a silent one.

Re-open when a customer engagement makes this gap block a deployment; the
`WPAD`/PAC path already generalizes cleanly to "read the OS's proxy config and
feed handle_the_pac_url through the existing `evaluatePac` seam" as the likely
shape of the fix, so landing this later does not require redesigning the
discovery precedence — only adding a fourth leg, ordered per SPEC.md §7's own
listed intent.
