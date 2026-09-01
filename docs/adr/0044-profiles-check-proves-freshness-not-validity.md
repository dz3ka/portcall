# ADR-0044: `profiles:check` proves the embed is fresh, not that a profile is valid

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

ADR-0003 made profiles data: YAML in `profiles/`, embedded as **text** into
`src/profiles/builtin.generated.ts` by `scripts/embed-profiles.mjs`, with
`npm run profiles:check` failing the build when the committed generated file has
drifted from its source. That check runs first in `npm run verify` and it runs
in CI on all three OSes. It has been green since M1, and it is easy to read it
as "the profiles are checked".

It is not. `--check` regenerates the file in memory and does a string compare:

```js
if (current !== output) {
  console.error('src/profiles/builtin.generated.ts is stale; run: npm run profiles:embed');
```

That is a freshness proof and only a freshness proof. Every property it
establishes is about the *relationship* between `profiles/*.yaml` and the
generated file — never about the contents of either. The embed step never calls
`parseProfile`, never touches `profileSchema`, and is written in `.mjs` outside
the TypeScript project on purpose, so nothing about it can reach the zod schema.

Before this ADR, **no test in the repo parsed any shipped profile through the
schema.** `test/profile-loader.test.ts` and `test/profile-schema.test.ts` are
both thorough and both run entirely against `test/fixtures/profiles/*.yaml` —
hand-written files that exist to exercise the failure table (unknown key, bad
hostname, bad port, duplicate endpoints, malformed YAML). The one exception,
`loadProfile('generic-ai-tool')`, was written to prove the built-in *lookup
path* works and happened to parse one real profile as a side effect. It named
that profile by string literal, so it would have kept passing untouched while a
new sibling profile was broken.

The failure this leaves open is specific, and M5 is exactly when it becomes
reachable, because M5 is when profiles stop being one file somebody wrote and
start being a set that grows by PR:

1. A profile picks up a key the `.strict()` schema rejects — a `region:`, a
   plural `hosts:`, an `expect_streaming` indented one level too far so it
   becomes an unknown top-level key. All are ordinary YAML mistakes.
2. `profiles:embed` embeds it, because it embeds *text*.
3. `profiles:check` passes, because the generated file matches a regeneration
   of itself.
4. `lint`, `typecheck` and `test` pass, because the broken bytes are inside a
   string literal and nothing parses that literal.
5. CI is green on ubuntu, macOS and Windows. The tag ships.
6. An FDE runs `portcall check --profile cursor` on a customer's laptop, on the
   afternoon that laptop was the whole point, and gets a `ProfileError` and
   exit 3.

Exit 3 is `--profile`-shaped (ADR-0006), so the person in the room reasonably
concludes they typed the flag wrong, and spends the meeting on it. The tool's
one job is to be the thing that works when nothing else does; failing at
argument-parse time on its own shipped data is the worst way to lose that.

The same gap covers a quieter case: the shipped *set*. `builtinProfileIds()` is
whatever `Object.keys` returns over the generated record, which is whatever
`readdirSync` returned, sorted. Nothing asserted what that set should be, so
adding, dropping or renaming a public profile id was an unreviewed consequence
of a filename.

## Decision

The shipped profile set gets its own test, `test/profiles-shipped.test.ts`, with
exactly two assertions:

1. **Every entry in `BUILTIN_PROFILE_SOURCES` parses.** The test loops the
   embedded record and runs each source through
   `parseProfile(id, 'builtin', text)` — the same function the binary calls, so
   the schema, the duplicate-endpoint check and the YAML parser all run against
   the exact bytes that ship. `parseProfile` throws a `ProfileError` naming the
   id and the failing path, so the throw is allowed to propagate rather than be
   wrapped: the native message is the better report.
2. **`builtinProfileIds()` equals exactly `['claude-code', 'cursor',
   'generic-ai-tool']`.** This is the only thing in the tree asserting M5's
   "three shipped profiles" exit criterion, and it makes any change to a public
   `--profile` id a reviewed diff rather than a filename's side effect
   (ADR-0043). The ids are sorted before comparison, so the assertion cannot
   depend on directory order across the three CI runners.

The test reads only the generated module — never `profiles/` from disk.

## Alternatives considered

- **Widen `profiles:check` to parse each profile.** Rejected. The embed script
  is deliberately plain `.mjs` outside the TypeScript project, because it has to
  run before `typecheck` in `verify` and before the build. Importing the zod
  schema into it either drags the type-stripping runtime requirement into the
  build's first step or forces a duplicate schema in JavaScript — and a
  duplicate schema is a second answer that can silently disagree with the first.
  The test suite already has the schema loaded and the discipline for it.
- **A second on-disk parse: `readdirSync('profiles/')` and parse each file.**
  Rejected as re-proving `profiles:check`. That check already establishes that
  the generated map is a byte-exact function of `profiles/`, on every `verify`
  and in CI. If the embedded text parses and the embed is fresh, the on-disk
  text parses; the extra `readdirSync` adds a cross-platform path dependency and
  a second thing to keep in step, in exchange for a property already held.
- **An "embedded keys == on-disk filename stems" assertion.** Rejected for the
  same reason, and it is the weaker half of the same claim: assertion 2 already
  pins the exact ids to literals, which is a stronger statement than pinning
  them to whatever the directory happens to contain.
- **Four assertions instead of two** (parse embedded, parse on-disk, ids match
  literals, ids match stems). Rejected: two of the four are the two above. A
  test file whose failures cannot each be traced to a distinct cause trains
  people to skim it.
- **A network smoke test that connects to every newly declared host in CI.**
  Rejected on SPEC.md §4: it makes third-party egress from CI on every push, to
  hosts chosen by a data file, which is precisely the behaviour this project
  tells customers it does not have. The property being claimed here is that the
  shipped profiles parse — that is a parse gate, and it should be tested as one.
  Whether the hosts are reachable is the *customer's* answer, produced by
  running the tool, which is the whole product.
- **A regex guardrail asserting every endpoint carries a `# source:` comment.**
  Rejected and recorded in ADR-0043: `parseProfile` discards comments, so the
  check would be a regex over three data files, standing in for a code review it
  cannot do as well.
- **Leaving it, on the grounds that a broken profile would be caught in
  review.** Rejected because it was not — this gap existed through four
  milestones and was found by reading the embed script, not by using the tool.
  Review catches a wrong hostname, which is a judgement a human is good at. It
  is poor at spotting one over-indented line inside a YAML block, which is
  exactly what a parser is for.

## Consequences

A profile PR now fails in `verify` and in CI when the YAML is invalid, on the
contributor's machine, before it can reach a customer's laptop. Adding a fourth
profile deliberately fails assertion 2 until the ids literal is updated, which
is the intent: the shipped set is a decision, and it should cost one line of
diff to change and one line of diff to review.

`profiles:check` keeps its narrower job and its honest name. This ADR exists so
that nobody reads its green line as more than it is again — the two checks are
complementary and neither substitutes for the other: `profiles:check` says the
embed matches the sources, `profiles-shipped.test.ts` says the sources are
loadable.

Still not covered, and stated plainly: nothing here checks that a declared host
is *correct*, current, or that the vendor still publishes it. That is a human
question, ADR-0043's `# source:` citations are the tooling for it, and a test
that appeared to answer it would be worse than the absence of one.
