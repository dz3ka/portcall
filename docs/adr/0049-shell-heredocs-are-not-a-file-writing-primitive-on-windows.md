# ADR-0049: Shell heredocs are not a file-writing primitive on this Windows toolchain

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

This is a process decision rather than a source-code one, recorded here because
the working agreement asks for an ADR whenever a convention changes and because
the failure it addresses cost this repository real time across several sessions
of M4 and M5.

Portcall is developed on Windows, with the agent's shell tool running Git Bash
(MSYS2) rather than `cmd.exe` or PowerShell. The natural way to write a file
from a shell is a heredoc:

```
cat > docs/some-file.md <<'EOF'
...content...
EOF
```

The quoted delimiter is supposed to make the body literal — no parameter
expansion, no command substitution, no backslash processing. On this toolchain
that guarantee does not hold reliably, and it fails in two distinct ways.

The first is loud. A body containing backticks, regular expressions, or nested
quote characters can abort with `unexpected EOF while looking for matching
quote`, and nothing is written. That is the benign failure: it is obvious, and
the immediate instinct — retry the same heredoc — merely wastes another attempt.
It happened while the `/handoff` skill tried to write a handoff document, again
when the same document was written by hand the following session, and a third
time while the retrospective that prompted this ADR was being drafted.

The second is quiet, and it is the one that motivates the rule. The body can be
written *successfully* with backslashes or quotes collapsed, producing a file
that looks plausible and is wrong. A prior session in a sibling repository wrote
`ship-status.json` through a Bash heredoc containing Windows paths; the
backslashes were mangled, the file stopped being valid JSON, and because nothing
in the tooling validates that file's syntax, every consumer failed silently
across at least one session boundary before a routine rewrite happened to catch
it.

The same class of corruption appeared in this milestone from a different
direction. Running `cosign verify-blob` with
`--certificate-identity-regexp "^https://github\.com/dz3ka/portcall/…"` produced
`failed to verify certificate identity: no matching CertificateIdentity found`
against a signature that was in fact valid — MSYS path conversion had rewritten
every `\.` in the argument to `/.` before cosign ever saw it. That error is not
visually distinguishable from a genuinely unverifiable release artifact. It was
caught only because cosign echoes back the regex it actually received.

The unifying observation is that the MSYS layer rewrites the bytes of shell
arguments and heredoc bodies in ways that are invisible at the call site, and
that markdown, JSON, YAML and regex — the four content types this project writes
most — are all built from exactly the characters it rewrites.

## Decision

Shell heredocs are no longer used to write files whose content contains
backticks, regular expressions, or nested quotes. Such files are written with
the `Write` tool, or through a Python heredoc where the content must be computed
rather than supplied literally. Shell heredocs remain acceptable for plain
unquoted text — a commit message body is the common case, and this repository
uses `git commit -F -` with one routinely.

Where a shell heredoc is genuinely the only available mechanism, the content is
written and verified in small appended chunks rather than as one large block, so
a failure is localised and a silent corruption is caught by the verification of
the chunk that carries it.

Separately, and for the same underlying reason: any shell argument containing
backslashes that must survive verbatim — a certificate identity regex being the
motivating case — is passed with `MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1`
set, and the tool's own echo of the argument is read back before its output is
believed.

This decision is adopted from the retrospective at
`2026-09-01-portcall-m5.md` in the retros store, which cleared it through the
rule-of-three gate: two prior retrospectives had recorded the same failure and
proposed the same fix, and the fix had been left unapplied both times.

## Alternatives considered

**Keep using heredocs and retry on failure.** Rejected because it only addresses
the loud failure mode. The retry costs one wasted attempt and is mildly
annoying; the quiet failure mode writes a corrupt file and is not detected by
retrying anything. A rule that fixes the visible half of a problem and leaves
the invisible half is worse than no rule, because it produces the feeling of
having handled it.

**Escape the problematic characters inside the heredoc body.** Rejected as
unreliable in the direction that matters. Getting the escaping right requires
knowing precisely which layer — MSYS argument conversion, Bash word splitting,
the heredoc reader — will touch a given byte, and that knowledge is exactly what
the failures above demonstrate is absent at the moment of writing. An escaping
scheme that is wrong produces the silent corruption rather than the parse error.

**Switch the agent's shell to PowerShell.** Rejected as disproportionate. It
would trade a known, bounded problem for an unknown set of new ones: PowerShell
5.1 has its own quoting rules, its own encoding defaults that differ between
`Out-File` and `Set-Content`, and its own native-executable stderr behaviour
that reports failure on a zero exit code. The project's shell usage is otherwise
working; the defect is specific to writing structured text through heredocs, and
so is the remedy.

**Record the workaround only in handoff documents.** This is the status quo, and
it is what failed. The workaround was already known and written down — twice, in
two prior retrospectives — and it was still hit a third time, including by the
tooling drafting the retrospective that recorded it. A fact that lives only in a
per-session document is re-lost at every session boundary; a rule in the working
agreement is loaded every session by construction.

## Consequences

The global working agreement at `~/.claude/CLAUDE.md` carries the rule directly,
so it applies to every repository worked on with this kit rather than to portcall
alone. That is the correct scope: the failure is a property of the host
toolchain, not of this codebase.

Nothing in portcall's source, tests, or CI changes as a result of this decision.
No file in the repository was written by a shell heredoc in a way this rule would
now forbid; the commit messages that used `git commit -F -` fall under the
plain-text exemption and remain valid.

The cost is a small loss of convenience. Writing a file through the `Write` tool
is one tool call rather than one shell line, and it cannot be composed into a
pipeline with other shell commands. That is an acceptable price for not silently
writing a malformed status file or misreading a valid signature as a forged one.

This ADR is deliberately about a failure that is not portcall's fault and not in
portcall's code. It is recorded publicly anyway, because the repository's stated
purpose is to show what forward-deployed engineering looks like, and a
substantial part of that work is discovering that the environment you were given
does not behave the way its documentation says it does — then writing the
finding down where the next person will find it.
