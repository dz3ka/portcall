# ADR-0005: Redaction is a typed boundary, on by default

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

The report is the deliverable, and the way it travels is that an operator emails
it to a vendor. It will contain internal hostnames, RFC1918 addresses,
usernames, machine serials and filesystem paths, because those are the evidence
that makes a finding credible. SPEC.md §4.4 sets the bar: the JSON that leaves
the customer's network must be safe to send without a legal review.

The obvious implementation is that each probe redacts what it emits. That is a
per-call-site rule, and per-call-site rules hold until the twentieth call site.
The failure mode is the bad one: nothing throws, nothing turns red, and an
internal hostname sits in a vendor's inbox until someone reads the report
closely, which is usually never.

## Decision

Redaction is one function at the boundary between the engine and the renderers,
and the type system makes crossing it mandatory.

`redact()` in `src/redact/index.ts` is the only producer of `RedactedReport`, a
branded type. `render()` accepts nothing else, there is no cast to that type
anywhere in the codebase, and a guardrail test asserts that. A probe therefore
has no path to output that does not pass through this file.

What gets hidden is decided by data classification, not by pattern matching:
every `Evidence` carries a `kind`, and the sensitive kinds (`hostname`, `ip`,
`username`, `serial`, `path`, `url`) are replaced by a salted SHA-256 token like
`<host:3f9a1c...>`, keyed by a per-report random salt. Hosts named in the active
profile are exempt — hashing `api.anthropic.com` protects nobody and makes the
report unreadable to the person who has to act on it.

`--no-redact` changes what `redact()` does; it never changes whether it is
called. One code path, so the off switch cannot drift into a second unreviewed
one, and the CLI prints a warning when it is used.

## Alternatives considered

- **Redact in each probe at emission.** Rejected: no mechanism behind the rule,
  and the author of the twentieth probe has to remember something the compiler
  will not remind them of. It also spreads a security-relevant decision across
  every file in the tree, which makes the ten-minute review impossible.
- **A regex sweep over the rendered output.** Rejected: it has to guess.
  Internal hostnames look like every other token; a sweep aggressive enough to
  catch `build-07.corp.local` also mangles the remediation text, and one gentle
  enough to keep remediation readable misses the hostname.
- **Reversible tokenisation with a key.** Rejected: it introduces a key, which
  introduces key management, which is precisely the conversation this tool is
  meant to shorten. A one-way hash needs no secret and no custody story.
- **An unsalted hash, or one fixed salt.** Rejected: a 12-hex-character hash of a
  short internal hostname falls to a wordlist immediately, and a fixed salt lets
  two reports from the same customer be correlated by anyone holding both.
- **Redaction off by default, `--redact` to opt in.** Rejected for the boring
  reason: the operator is in someone else's building, under time pressure, and
  the default is what actually ships. A safe default that is occasionally
  inconvenient beats a safe flag that is occasionally remembered.

## Consequences

Adding an evidence kind is a decision made in one file, and a reviewer auditing
"what can leave the network" reads that file and the renderers, nothing else.

Tokens are not stable across runs, so two reports from the same machine cannot
be diffed by token. That is the deliberate cost of the per-report salt. If it
ever becomes load-bearing the answer is an explicit operator-supplied `--salt`,
not a constant baked into the binary.

The `text` and `number` kinds are probe-authored and pass through unredacted, so
a probe *can* still smuggle an identifier into free text. The type system does
not prevent that; the rule that identifiers have their own kinds, plus review,
is what does. Naming that limit is better than implying the boundary is total.
