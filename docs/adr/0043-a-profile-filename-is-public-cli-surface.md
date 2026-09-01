# ADR-0043: The named profiles are Claude Code and Cursor, and a profile filename is public CLI surface

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

M5 ships three profiles. Until this decision the repo had one,
`profiles/generic-ai-tool.yaml`, and ADR-0003 had already settled the mechanism:
a profile is a YAML file in `profiles/`, adding a vendor is a PR, and the
release embeds the text. What ADR-0003 deliberately did not settle is *which*
vendors get a named file, or what the file is called.

The naming question is not cosmetic, and the loader is why. `loadProfile` sends
an argument down one of two paths, and `looksLikePath` decides which:

```ts
return id.includes('/') || id.includes(WINDOWS_SEPARATOR) || /\.ya?ml$/i.test(id);
```

A bare word is looked up directly in `BUILTIN_PROFILE_SOURCES`, whose keys
`scripts/embed-profiles.mjs` derives by stripping `.yaml` off each filename.
There is no alias table, no normalisation step, and nowhere to put one without
inventing a layer. So `profiles/cursor.yaml` *is* `--profile cursor`, and
renaming the file later is a breaking change to a published command line —
the kind that lands in somebody's runbook, their CI job, and the screenshot in
their internal wiki. The stems are API from the first tag, exactly as finding
ids already are (CLAUDE.md, "Finding `id`s are stable and greppable ... Once
public, treat them as API").

The second force is what a declared endpoint *does*. SPEC.md §4's third
non-negotiable is that portcall makes no network call except to hosts named in
the active profile. Read the other way round, naming a host in a profile is the
single act that authorises portcall to open a socket to it from inside a
customer's network. A profile is therefore not documentation about a vendor; it
is a standing egress authorisation that ships in the binary. A host that got
into a profile because it seemed right is an unauthorised connection attempt
made on somebody else's network, logged by their proxy, under our name.

## Decision

The two named profiles are **Anthropic Claude Code** (`profiles/claude-code.yaml`)
and **Cursor** (`profiles/cursor.yaml`). The filename stem is the verbatim
public `--profile` id: `--profile claude-code`, `--profile cursor`. Both are
treated as API from the first tag and change only through an ADR that
supersedes this one.

Every endpoint in both files carries a `# source:` comment naming the vendor's
own published network-access page, and **an endpoint that cannot be cited does
not ship**. The sources used are
`https://code.claude.com/docs/en/network-config` and
`https://cursor.com/docs/enterprise/network-configuration` — in both cases the
vendor's own firewall/allowlist documentation, not a blog post, not a forum
thread, and not recall. Where fewer hosts could be cited than expected, fewer
hosts ship.

Two corollaries follow from the citation rule and are visible in the files:

- **Wildcards do not become endpoints.** Cursor's page recommends allowlisting
  `*.cursor.sh` and three sibling patterns. A profile endpoint is a concrete
  host portcall connects to; a wildcard has nothing to connect to, and
  expanding one means inventing names the vendor never published. The
  granular list on the same page is what ships.
- **Location-dependent hosts do not become endpoints.** Cursor's regional Tab
  hosts (`api4`, the three `*.gcpp.cursor.sh` names) are cited, but which one a
  given customer uses depends on where they are. Probing all three would emit
  two failures every customer would be right to ignore, which is a slower way
  of emitting no signal at all.

`required: true` is set only where the tool is non-functional without the
endpoint; everything else is optional so `cap()` degrades rather than blocks.
Neither profile declares `doh_resolvers` — per ADR-0007 declaring one asserts
the tool uses that resolver, and neither vendor documents one.

## Alternatives considered

- **Vendor-prefixed ids (`anthropic-claude-code`, `anysphere-cursor`).**
  Rejected. It is tidier in a directory listing and worse at the only moment
  that matters, which is an FDE typing a flag into someone else's terminal with
  a security lead watching. `--profile claude-code` is what a person guesses;
  `--profile anthropic-claude-code` is what a person looks up. The `name:`
  field inside the file already carries the full vendor attribution
  (`Anthropic Claude Code`), which is where a report header wants it and where
  a command line does not.
- **A `generic` alias for `generic-ai-tool`.** Rejected, and specifically
  rejected as *new API rather than a convenience*. No alias exists today —
  `looksLikePath` diverts only on a separator or a YAML extension, and
  `BUILTIN_PROFILE_SOURCES` is a plain keyed record. Adding `generic` means
  adding an alias layer, and an alias layer means two spellings of one profile
  in every report header, every support thread and every runbook, forever, to
  save eight characters once. If a shorter name is wanted, the right move is an
  ADR renaming the file before the first tag, not a second name for it after.
- **Shipping one large "AI coding tools" profile covering both vendors.**
  Rejected on the egress rule above: it would make every check run contact
  every vendor's hosts, so a customer evaluating Cursor would have portcall
  connect to Anthropic's API from inside their network, unasked. It also makes
  the exit code meaningless — a blocker for a tool the customer is not
  deploying is noise that has to be explained away, and a summary somebody
  learns to explain away is a summary nobody reads.
- **Deriving endpoints from each vendor's published IP ranges instead of
  hostnames.** Rejected for a boring reason: this tool exists because DNS,
  proxies and TLS interception sit between the laptop and the address, and an
  IP-range check skips all three of the things that actually break.
- **Filling gaps from memory where a vendor's page is thin.** Rejected: it is
  the one failure mode of this package that a customer's security team would
  catch before we did, and they would be right. If only two hosts can be cited
  for a vendor, two hosts ship, and the profile is honestly incomplete rather
  than dishonestly complete.

## Consequences

`--profile claude-code` and `--profile cursor` are now public strings. Renaming
either file breaks a customer's command line, so a rename requires a superseding
ADR and, realistically, keeping the old file as well. That cost is accepted
deliberately: it is the price of not building an alias layer, and it is paid
once per name rather than on every lookup.

Profiles now age. A vendor moves a host, adds an auth domain or retires a CDN on
their schedule, and the shipped file silently describes last quarter's network.
There is no mechanism here that notices, and deliberately none that fetches the
page at run time (ADR-0003 rejected run-time fetching, and the reasons hold:
this tool runs inside networks that may be blocking us). The mitigation is the
`# source:` line — a reviewer refreshing a profile has the exact page to
re-read, and a stale claim is a diff against a URL rather than an argument.

Deliberately not built: a test that scans the YAML for `# source:` comments.
`parseProfile` discards comments before anything downstream sees them, so such a
test would be a regex over three data files, guarding a rule that a human
reviewer applies better — machinery standing in for a code review. The rule
lives in this ADR and in the file headers, which is where the reviewer already
looks.

Both files are recorded here as Node-runtime profiles (`runtimes: [node]`),
which is what drives the M4 trust-store cross-check. Claude Code's own page
documents that it reads the OS trust store on a recent enough runtime; Cursor is
an Electron client. If either vendor's runtime story changes, the `runtimes:`
line is the field to revisit, and it is one line.
