# ADR-0033: The OS trust store is read through a pinned argv table, not a banned word

- **Status:** Accepted — retroactive write-up. The decision was made and landed
  on 2026-08-28 in `c3130c9` ("Read the OS trust store through a pinned argv
  table, not a banned word"), whose message names it and ADR-0032 as M4's docs
  pass; the write-up slipped past that milestone and the citations arrived
  first. Nothing below is new — it is the reasoning already carried in that
  commit, in `src/net/os-truststore.ts`'s header, and in the two guardrails
- **Date:** 2026-09-01 (decision: 2026-08-28)
- **Deciders:** Bogdan Dzekic

## Context

M4 has to answer "which roots does *this machine* trust", and the honest way to
ask is the platform's own certificate-listing command. That is also the most
dangerous thing portcall has done: a subprocess is where "read the public
certificates" turns into "read the private key" by a one-word edit nobody
reviews closely. `security find-certificate` and `security export` differ by one
argument. `Cert:\LocalMachine\Root` and `Cert:\LocalMachine\My` differ by four
characters.

The control that existed was textual: `no-credential-access.test.ts` banned the
words `/keychain/i` and `/security find-/i` anywhere in `src/`. That control had
to change, because on macOS the only shipped way to enumerate public anchors
names a keychain file, and the remediation strings have to name it too. But
ADR-0025 forbids weakening a guardrail to buy a green run, so the amendment had
to be a net strengthening rather than a hole.

It is also the wrong *shape* of control. Banning a word forbids the vocabulary
the sanctioned read needs while permitting the twenty other ways to reach a
private key — `certutil -exportPFX`, an `X509ContentType::Pkcs12` export,
`keytool -storepass`, `~/.ssh`. The ban was cheap, and it was not aimed at the
thing that matters.

The same question arrives from the other side in `runtime-stores.ts`. Asking a
runtime about itself — `java -XshowSettings`, `python -m certifi`, `go env` —
means executing a binary found on a customer's `PATH`, with their
`JAVA_TOOL_OPTIONS` in scope, on a machine portcall does not own.

## Decision

**Exactly one file in `src/` starts a process, and it may start only commands
that appear verbatim in a frozen table of source literals.**

- `src/net/os-truststore.ts` is that file. Every other file in `src/` is
  process-free, and `test/guardrails/subprocess-boundary.test.ts` enforces both
  halves.
- The table lives between `// --- BEGIN PINNED COMMAND TABLE ---` and its `END`
  marker. Nothing inside that region may be interpolated, concatenated or read
  from the environment: no profile value, no hostname, no certificate field.
- `file` is a fixed absolute path — `/usr/bin/security`,
  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` — never resolved
  through `PATH`, and `shell: false` means there is no shell to inject into.
- **Public certificates only.** Three rows: the macOS system-root and
  admin-anchor keychains, and the Windows machine `Root` store. The user's own
  stores — the macOS login keychain, Windows `CurrentUser`, either `My` store —
  are not in the table and must never be. Linux reads a world-readable bundle
  file directly and starts no process at all.
- `locator` is its own literal rather than derived from `argv`, even though on
  darwin the two are the same string: deriving it would be a value built at run
  time inside the pinned region, which is the one thing that region forbids.
- The guardrail asserts the whole table element by element, **written out rather
  than imported**, so a table that asserts itself is impossible. A new
  invocation is not a diff a reader has to notice; it is a red test.
- **Runtime store discovery is file paths and environment variables only.**
  Nothing in `runtime-stores.ts` starts a process, and no trust-store tool name
  may appear there — the credential guardrail scans every `src/` file outside
  the reader and trips on a doc comment, which is the intended pressure.
- The credential guardrail's two word-bans are replaced by the item classes
  SPEC.md §4.2 actually forbids (`-store My`, `HasPrivateKey`,
  `X509ContentType`, `.pfx`, `storepass`, `keypass`, `id_rsa`, …), plus a case
  asserting that the two sanctioned reads match nothing.
- The child's stderr is drained and discarded. Customer prose can be in it and
  there is no redaction pass for a field that does not exist; only a machine
  code crosses into an outcome (ADR-0009).
- SPEC.md §4.2 is amended in the same change to say what portcall *does*
  execute. A rule the code visibly breaks is worse than no rule.

## Alternatives considered

- **Keep the word bans.** Rejected: they forbid the sanctioned read along with
  the forbidden ones while permitting every route that does not happen to spell
  "keychain". The replacement is a net strengthening — "here is the complete,
  byte-pinned list of every external process portcall may start, exactly one
  file may start them, exactly one file may name them" — which is what makes it
  legal under ADR-0025.
- **Resolve the tool through `PATH`.** Rejected for the boring reason: this runs
  on a customer's laptop, whose `PATH` is theirs — shims, wrappers, whatever a
  corporate MDM image put in front. An absolute path costs nothing and closes
  it.
- **Build the argv at call time from the store the caller asked for.** Rejected:
  a caller-supplied path interpolated into an argv is exactly the edit that no
  text pattern in `no-credential-access.test.ts` would catch, which is why the
  table is pinned element by element rather than scanned for suspicious words.
- **Import `OS_TRUSTSTORE_COMMANDS` into the guardrail and assert its shape.**
  Rejected: the table would be asserting itself. It is written out in the test,
  not imported and reformatted, so the two copies must be edited together.
- **Ask each runtime where its trust store is.** Rejected: it executes a
  customer binary off their `PATH` with their environment in scope — the exact
  thing this rule exists to prevent — and it is slower and less deterministic
  than a `stat`.
- **Buffer the child's stderr for diagnostics.** Rejected on the boring reason:
  customer prose ends up in it, and there is no redaction pass for a field the
  outcome does not have. A machine code is enough to file a ticket against.
- **Put `TrustStoreCommand` beside the reader.** Rejected as a deviation the
  implementation took deliberately: the guardrail and the pure cross-check must
  name the type without importing the module that spawns processes, so the type
  lives in `net/types.ts`.

## Consequences

- Process safety is reviewable by reading one file and one test. Adding a
  platform or a store is a diff in two places, and they must move in the same
  commit.
- **A remediation string may not name a trust-store tool outside the reader.**
  Three strings drafted for WP6 named `certutil`, PowerShell and `security
  find-certificate`; the guardrail rejected them, rightly — a string naming a
  tool reads as a tool portcall runs. They name "the platform's certificate
  manager" in prose instead.
- The `store-not-found` remediation has to explain that portcall does not
  execute a toolchain it finds on `PATH`, because "we looked in these eight
  places" otherwise reads as incompetence rather than as a constraint.
- `reader-missing` can name the absolute path the tool was pinned to, which is a
  more actionable sentence than "not found".
- The Linux bundle has no row, so it has no ceiling and reports `budgetMs: null`
  (ADR-0037).
- The macOS patterns in the credential guardrail are matched loosely
  (`security` … `export`) because this repo spawns via argv arrays, which the
  shell-string form the design wrote simply does not see.
