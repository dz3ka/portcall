# Lesson 0002: A boolean that explained away its neighbour's failure

- **Date:** 2026-08-31
- **Commit:** `318d357`
- **Milestone:** M4, WP6.5-C

## What we built

`src/probes/truststore/evaluate.ts` cross-checks the trust store this machine
actually has (`osStores`, one entry per keychain/store the platform reader
enumerated) against the trust store each configured runtime (Node, Go, Python,
Java) will actually consult. Before this commit, every way a per-store read
could fail — the listing tool missing, the tool running and exiting non-zero,
its output exceeding the size portcall reads from a child process, the store
coming back empty — was funnelled into one aggregate `truststore.os.unreadable`
finding, gated behind a hand-rolled condition that decided, array-wide, whether
any of that was worth telling the operator about.

This commit deletes that gate. Each of the four failure kinds now produces its
own `truststore.os.unreadable` finding, naming its own store, with its own
remediation text — four remediations, two titles (`STORE_UNREADABLE_TITLE` for
three of them, `STORE_EMPTY_TITLE` for the fourth, because "the store never
answered" and "the store answered and was empty" are different claims about the
machine). It also fixes a real defect in the gate it replaces: a single
store's `timeout` or `aborted` outcome could silently swallow a *different*
store's genuinely unreadable outcome, and corrects a remediation hint that told
Node operators to go look in the wrong place. Net line count is up (evaluate.ts
grew by ~250 lines), but the *decision surface* shrank: there is no longer a
"should the aggregate fire" question to get wrong, because there is no
aggregate.

## The design decision

### Decision one: per-store findings instead of an aggregate gate

**The problem.** A single finding covering "the OS trust store cross-check
failed" cannot distinguish "nothing was there to read" from "something is
actively broken (wrong permissions, a corrupt keychain, a killed child)" —
both looked identical to an operator, and both got the same generic
remediation. Worse, a machine with five clean keychains and one broken one
produced *no signal at all* about the broken one if any other store on the
same run happened to be mid-timeout or mid-abort (see Decision two — that's
the actual bug this shipped alongside).

**The chosen approach.** A lookup table, `OS_READ_FAILURES`, maps each of the
four failure kinds a reader can actually produce to a `{ title, remediation }`
pair, and `unreadableFinding(store)` is called once per failed store inside
the per-store loop — never after it, never aggregated. This is the same
pattern CLAUDE.md's rule against collapsing operationally-distinct errors
("DNS vs connect-refused vs timeout vs TLS vs HTTP are four different teams")
applies at the level of *table rows* instead of a `switch` over network errors.

**Alternatives weighed:**

- **Keep one aggregate finding, but make its evidence array itemise every
  failed store.** This was close to what the old code already did (`failed
  .flatMap(...)`) and was rejected because the finding's *severity and
  remediation* still had to be one value for the whole array — you cannot
  write a single remediation string that is simultaneously "the tool wasn't
  installed" and "the tool ran and got killed" without it degrading into "go
  check your setup," which is the generic non-answer this WP exists to
  replace. One row, one root cause, one remediation is a constraint an
  aggregate structurally cannot satisfy once there are two-plus distinct root
  causes.
- **Keep the aggregate, but split it by failure kind (one aggregate per
  kind).** Better than a single aggregate, but still wrong at the *store*
  granularity: two `reader-failed` stores (say, both macOS keychains hit by
  the same broken tool) would still merge into one finding whose evidence array
  awkwardly repeats `store`/`code` pairs, and the finding's severity is still
  answering "did any store of this kind fail" rather than "which store, read
  from which locator, failed." The per-store shape composes better with
  everything downstream that already keys off individual `TrustStoreOutcome`
  objects (`anchorsPerStore`, `ceilingFor`).
- **No suppression at all — always emit** `truststore.os.read` **for every
  store, `ok` or not, and fold the failure reason into that one finding's
  evidence.** Rejected because `truststore.os.read`'s severity is hard-coded
  `ok` (line 480 of the new file) and is asserted as such throughout the test
  suite; overloading one finding id to sometimes mean "clean" and sometimes
  mean "broken" would break `assertRemediable`'s rule that only `blocker`/
  `degraded` findings must carry a remediation — a `truststore.os.read=ok`
  with a hidden failure would need one anyway, silently changing the contract
  every reader of the finding id already depends on.

The pattern here is **exhaustive case tables over hand-rolled aggregation
conditions** — the same shape as an HTTP client mapping status codes to
typed errors instead of one `RequestFailed` catch-all, or a state machine
where every transition gets its own guard clause instead of one shared
"something went wrong" branch.

### Decision two: the array-wide boolean that explained away a sibling's failure

Read the deleted code carefully (`git show 7cd6ace:src/probes/truststore/evaluate.ts`,
the `osFindings` function before this commit):

```ts
const explainedElsewhere = input.osStores.some(
  (store) => store.failure === 'timeout' || store.failure === 'aborted',
);
if (input.osStores.length === 0) {
  findings.push(unreadableFinding([...], true));
} else if (osEvidenceLevel(input.osStores) === 'none' && !explainedElsewhere && failed.length > 0) {
  findings.push(unreadableFinding(failed.flatMap(...), false));
}
```

`explainedElsewhere` is computed with `.some()` over the *entire* `osStores`
array — it answers "does **any** store in this run have a timeout or an
abort," not "does **this** store." The new test `names the store that failed,
distinctly from the one that timed out` (`test/truststore-evaluate.test.ts`)
pins down exactly the scenario that flag got wrong: one macOS keychain times
out, a second, unrelated keychain gets `reader-failed`. Under the old code,
`explainedElsewhere` is `true` because *a* store timed out, so the aggregate
branch — the only place a `reader-failed` outcome could ever produce a finding
— never fires. The timed-out store gets its own `truststore.os.read-timeout`
finding (that branch is unconditional, per-store), but the `reader-failed`
store gets nothing: no `os.read` (its `failure` is non-null), no
`os.unreadable` (suppressed by the neighbour's timeout), nothing. It vanishes
from the report as completely as a store that was never enumerated, on a
machine where something was, concretely, broken.

This is the second sense in which "suppression gate" was the right word for
the old design: it was not just coarse, it had a **scoping bug** baked into
its coarseness — a per-store fact (did *this* store's failure get explained by
its own finding) was being decided by a run-wide predicate (did *any* store
get explained). The fix isn't a smarter boolean; it's removing the boolean.
Once every failure kind gets its own per-store `case` in the switch, there is
no "was this already explained elsewhere" question left to answer wrong.

The commit message frames the fix partly through
`@typescript-eslint/switch-exhaustiveness-check`, and it's worth being precise
about what that lint rule did and didn't catch here. The rule enforces that a
`switch` over a union type handles every member (or has a `default`); it
flags a **missing case**, at compile time, in the *new* switch this commit
introduces. It would not, on its own, have caught the old `explainedElsewhere`
bug — that bug lived in a boolean built from `.some()` over an array, not in
an incomplete switch. What the rule bought here is different and still real:
it is the guardrail that makes it *hard to reintroduce* this class of bug
going forward, because the replacement code is structured as one switch with
one case per failure kind rather than a chain of conditions layered with a
side aggregate. The lint rule turns "did I handle every case" from a thing a
reviewer has to check by re-deriving the union's members, into a thing the
compiler refuses to let compile if it's wrong.

### Decision three: naming what the runtime actually reads

`CONFIRM_LISTING_HINT` is new: a small per-runtime lookup used only when a
`missingRootFinding` is built over a `TrustSet` that was only partially read
(`set.partial`), to tell the operator how to confirm the finding by hand
before treating a `degraded` verdict as a `blocker`. Node's entry was wrong on
its face: it pointed at "the platform's own certificate manager" — but the
very next sentence in `missingRootRemediation`'s `node` case says outright
"Node does not read this machine's OS trust store." Sending an operator to
Keychain Access to confirm something about a store Node never reads is not a
shortcut, it's a wrong answer that happens to sound plausible. The only thing
that can partially populate what Node treats as trusted is
`NODE_EXTRA_CA_CERTS` — a file — so that's what the corrected hint names. This
is worth naming as its own lesson because it's not a logic bug the type
checker or a test could catch: `'the platform's own certificate manager'` type-checks
fine as a `string`, runs fine, and is simply false about what the software
does. The fix is a documentation-grade discipline applied to a string a
customer reads: **a remediation must name the mechanism the runtime actually
consults, not a mechanism that sounds like it should apply.** The commit notes
this path is currently dead code in production — no real reader sets
`TrustSet.partial: true` today, only test fixtures do — which makes it exactly
the kind of defect that survives silently until the day a partial-read path
actually gets wired up, at which point it starts actively misdirecting
operators.

## Code deep-dive

This is a TypeScript diff, not Go or Rust, so there's no goroutine-lifecycle
or borrow-checker material here. What's genuinely instructive is TypeScript's
*type system* doing work that Rust's `enum` + `match` gets for free at compile
time, and Go gets only via a third-party linter — worth walking through
precisely because the "same bug, three languages, three different levels of
compiler help" comparison is exactly the kind of transferable intuition this
project is meant to build.

### 1. The exhaustive switch, and what actually enforces it

```ts
switch (store.failure) {
  case null: { /* ... */ continue; }
  case 'timeout':
    findings.push(readTimeoutFinding(store, ceilingFor(store.kind, input.osCommands)));
    continue;
  case 'aborted':
    findings.push({ /* ... */ });
    continue;
  case 'unsupported-platform':
    // Never true of a real store: `types.ts`'s own doc says this value is
    // synthesised by the probe from an *empty* `osStores` array, never
    // assigned by a reader. Listed explicitly, doing nothing, so that
    // `@typescript-eslint/switch-exhaustiveness-check` keeps every branch
    // below this one - `OS_READ_FAILURES`'s four keys - honest rather than
    // silently swallowed by a `default`.
    continue;
  case 'reader-missing':
  case 'reader-failed':
  case 'output-too-large':
  case 'no-certificates':
    findings.push(unreadableFinding(store));
    continue;
}
```
`src/probes/truststore/evaluate.ts`, inside `osFindings`

`store.failure` has type `TrustStoreFailure | null`, and `TrustStoreFailure`
(`src/net/types.ts:215-222`) is a seven-member string-literal union. Plain
TypeScript's control-flow analysis will happily let this `switch` compile with
only three cases handled — a `switch` that falls off the end without a
`default` is not a type error in `tsc` by itself, because `tsc` doesn't treat
"exhaustiveness over a switch's subject" as a thing it checks unless you force
it (the classic idiom is a `default: { const _exhaustive: never = store.failure; }`
line, which *does* work through plain `tsc` but has to be written by hand,
every switch, and silently stops working the moment someone adds a `default`
that does something else). This repo instead turns on
`@typescript-eslint/switch-exhaustiveness-check: 'error'` in `eslint.config.js`
— an ESLint rule, not a compiler feature — which inspects the switch's subject
type and errors if any member of the union has no case. That's why the
`'unsupported-platform'` case exists and does nothing: without it listed
explicitly, the lint rule would flag the switch as non-exhaustive, even though
that value is a real member of `TrustStoreFailure` that this function is
documented to never actually see (it's synthesized by the *caller*, from an
empty array, never assigned to a `store.failure` field).

Compare this to what the equivalent code looks like in Rust and in Go:

- **Rust.** `TrustStoreFailure` would be an `enum` with seven variants, and
  `match store.failure { ... }` is exhaustive-checked by `rustc` itself, no
  lint plugin required — a missing arm is `error[E0004]: non-exhaustive
  patterns`, at the same compiler pass that checks types. There is no
  equivalent of "someone deletes the lint config and this silently stops being
  checked," because the enforcement isn't a lint, it's the type checker.
- **Go.** Go has no sum types at all — `TrustStoreFailure` would most likely
  be a `string` (or an `int`) with a set of `const` values, and a `switch`
  over it has *no* compiler-enforced exhaustiveness whatsoever, string or
  `iota`. The closest tooling equivalent is `staticcheck`'s `SA... `
  exhaustive-style analyzers or the third-party `nishanths/exhaustive`
  linter, run the same way this repo runs `@typescript-eslint/switch-
  exhaustiveness-check` — bolted on via CI, not the language.

So the ordering, strongest to weakest guarantee, for "did I forget a case": Rust
(compiler, unconditional) > TypeScript-with-this-lint-rule (CI-enforced,
removable) > TypeScript-without-it or Go-without-`exhaustive` (nothing, a
human has to notice). The `explainedElsewhere` bug in Decision two lived in
exactly that gap — it wasn't a missing switch case at all, it was a boolean
built from `.some()`, which no exhaustiveness check of any kind can catch,
because there was no union being switched over in the first place. The lesson
generalizes: exhaustiveness checking only catches "I forgot to handle a case
of this union." It cannot catch "I handled every case, but the *scope* of one
handler's guard condition is wrong." That second bug class needs a test that
actually constructs the adversarial combination — which is exactly what
`names the store that failed, distinctly from the one that timed out` does.

### 2. A `Record` keyed by a computed subset of the union

```ts
const OS_READ_FAILURES: Readonly<
  Record<Exclude<TrustStoreFailure, 'unsupported-platform' | 'timeout' | 'aborted'>, { title: string; remediation: string }>
> = {
  'reader-missing': { title: STORE_UNREADABLE_TITLE, remediation: '...' },
  'reader-failed': { title: STORE_UNREADABLE_TITLE, remediation: '...' },
  'output-too-large': { title: STORE_UNREADABLE_TITLE, remediation: '...' },
  'no-certificates': { title: STORE_EMPTY_TITLE, remediation: '...' },
};
```
`src/probes/truststore/evaluate.ts`

`Exclude<TrustStoreFailure, 'unsupported-platform' | 'timeout' | 'aborted'>`
is TypeScript's built-in conditional-type utility computing a *type*, not a
value: it distributes over `TrustStoreFailure`'s seven members and keeps only
the ones not named, leaving exactly the four-member union `'reader-missing' |
'reader-failed' | 'output-too-large' | 'no-certificates'`. `Record<K, V>` then
requires an object with *exactly* those four keys and no others — add a fifth
key and it's a type error (excess property), omit one and it's a type error
(missing property), and — this is the part worth sitting with — if `types.ts`
ever adds an eighth `TrustStoreFailure` member, this `Record` does **not**
silently compile; the object literal is now missing a required key and the
build breaks at the assignment. That's the same "the type is the single
source of truth, edit the union and the compiler finds every place that needs
updating" property Rust's `enum` gives you for free, achieved here without a
sum type by composing two structural-typing features (`Exclude`'s
distributive conditional type, and `Record`'s mapped-type requiredness). It's
worth noticing this is a two-step encoding of one invariant that a Rust
`match` arm or a Rust `enum`-keyed `HashMap` wouldn't need two steps for —
TypeScript's unions are just sets of literal types with no first-class
"variant," so getting compiler-enforced completeness out of them means
reaching for a generic utility type rather than a language keyword.

### 3. The guard that re-establishes an invariant the caller already proved

```ts
function unreadableFinding(store: TrustStoreOutcome): Finding {
  const failure = store.failure;
  // The caller (`osFindings`' switch) only reaches this branch after
  // excluding null/timeout/aborted/unsupported-platform, so this narrows to
  // exactly `OS_READ_FAILURES`'s four keys. The guard below is for the
  // compiler, which only knows the field's full declared type - the same
  // idiom `tls/evaluate.ts`'s `anchorOf` uses.
  if (failure === null || failure === 'timeout' || failure === 'aborted' || failure === 'unsupported-platform') {
    /* c8 ignore next */
    throw new Error(`unreadableFinding called with a failure it does not cover: ${String(failure)}`);
  }
  const { title, remediation } = OS_READ_FAILURES[failure];
  // ...
}
```
`src/probes/truststore/evaluate.ts`

This is worth pausing on because it looks redundant at first read — the only
call site is inside a `switch` case that has *already* narrowed `store.failure`
to exactly these four values, via the discriminated-union narrowing the
compiler performs on `switch (store.failure) { case 'reader-missing': ... }`.
So why re-check inside the function?

Because TypeScript's narrowing is **local to the control-flow graph of one
function** — it doesn't survive a function call boundary. Inside `osFindings`,
the compiler knows, at the point `unreadableFinding(store)` is called, that
`store.failure` is one of the four safe values. But `unreadableFinding` is a
separate function with its own parameter, typed `store: TrustStoreOutcome`,
whose `failure` field is declared as the *full* `TrustStoreFailure | null`.
Nothing in TypeScript's type system lets a function's parameter type be
narrower than its declared type based on who happens to call it — there's no
mechanism (short of overloads, which don't apply to object-shaped parameters
like this) for "this parameter is `TrustStoreOutcome`, but only the callers in
this one switch arm may pass one whose `failure` is one of these four
values." That's a fact the *caller* knows and the *type system* does not
propagate into the callee's parameter type. So `OS_READ_FAILURES[failure]`
inside the function body, without the guard, would type-check against `failure:
TrustStoreFailure`, and `OS_READ_FAILURES` doesn't have a `'timeout'` key —
TypeScript would correctly refuse to compile `OS_READ_FAILURES[failure]` as
written, forcing exactly this guard (or an unsafe cast) to narrow the type
locally before the lookup.

The `throw` is doing double duty: it's the runtime check that would catch a
real defect (someone adds a fifth call site that doesn't actually go through
the switch), and it's also what performs the compile-time narrowing —
after the `if` returns via `throw`, everything past it, the compiler statically
knows `failure` can only be the four remaining literals, exactly what
`OS_READ_FAILURES` is indexed by. This is the general TypeScript idiom for
"prove an invariant a caller established but the type system can't carry
across a call": guard-and-throw at the boundary, narrow for the rest of the
function body. Rust's equivalent tool for the same shape of problem is
different in kind, not degree: an `enum` with only the relevant four variants
passed as the parameter type *is* the proof, checked at the call site by the
compiler, with no runtime check needed at all — which is the version of this
function you'd write if `TrustStoreOutcome.failure` in this codebase were
Rust's `enum` rather than TypeScript's string-literal union, and is a good
illustration of why "make illegal states unrepresentable" is preached so
heavily in the Rust community: the guard-and-throw here is the tax you pay
for not having a type that could express "one of these four, never those
three" as the parameter's declared type in the first place.

### 4. Conditionally including a field, without an `undefined` sitting in the object

```ts
findings.push({
  id: 'truststore.os.read',
  // ...
  evidence: [
    // ...
    ...(unparsed > 0 ? [{ label: 'unparsable certificates', value: String(unparsed), kind: 'number' as const }] : []),
  ],
  ...(unparsed > 0 ? { remediation: unparsedRemediation(unparsed) } : {}),
});
```
`src/probes/truststore/evaluate.ts`

Both spreads answer the same question — "should this key/element exist at
all" — with the same idiom: spread either a one-element array/object or an
empty one into a literal. The alternative, `remediation: unparsed > 0 ?
unparsedRemediation(unparsed) : undefined`, would also satisfy `remediation?:
string`'s type (optional fields accept an explicit `undefined`) and would
satisfy `assertRemediable` identically, since it only checks
`=== undefined`. The reason the spread form is preferred here isn't type
safety, it's what the *object itself* looks like afterward:
`{ remediation: undefined }` is a key present with value `undefined`, while
the spread form omits the key entirely when the condition is false —
`Object.keys(finding)` differs, `JSON.stringify` differs (`JSON.stringify`
drops `undefined`-valued keys but only implicitly; a test asserting the
finding's shape would still see the key with the spread-omitted version
guaranteeing it's simply absent, not "absent because JSON dropped it"), and a
reader scanning the object literal sees a field that's structurally not there
rather than a field whose presence they have to reason about against its
value. `as const` on the evidence branch's `kind: 'number'` is there because
without it, TypeScript would widen the literal `'number'` to the general
`string` inside the array literal, and `Evidence.kind` is a narrow union
(`EvidenceKind`) — the array element wouldn't type-check as `Evidence` without
the annotation pinning it back down to the literal type.

## What would break

**The failure modes this design now handles that the old one didn't:**

- Two stores failing two different ways in the same run (the exact scenario
  `explainedElsewhere` mishandled). Each now gets its own finding, naming its
  own store, its own locator, its own failure code.
- A store that's genuinely unreadable on a machine where *no other* store
  failed. This always worked, but for the wrong-looking reason — the old
  aggregate's condition happened to be satisfiable in the single-failure case;
  it just also happened to be *un*satisfiable the moment a sibling store had
  timed out or aborted, which is the kind of conditional correctness that only
  gets caught by a test built specifically to combine two failure kinds, not
  by exercising each failure kind in isolation (which is exactly what the old
  test suite did, and why the bug shipped and stayed unnoticed).
- A Node operator following `missingRootRemediation`'s advice literally. The
  old text sent them to a certificate manager Node never consults; the new
  text sends them to the one file (`NODE_EXTRA_CA_CERTS`) that can actually
  change what Node trusts.

**The bugs a newcomer to this pattern would plausibly introduce:**

- Adding a fifth `TrustStoreFailure` member to `types.ts` and forgetting to
  add its `OS_READ_FAILURES` row. Caught immediately, at the `OS_READ_FAILURES`
  assignment, by `Record`'s exhaustiveness — this is the "table drives the
  compiler" bet paying off. A newcomer relying on a `switch` with a `default:
  throw` instead of a `Record` would only find out at *runtime*, on whichever
  machine first hits the new failure kind — likely a customer's laptop, not CI.
- Writing `unreadableFinding`'s guard as `if (failure !== 'reader-missing' &&
  failure !== 'reader-failed' && ...)` (excluding by naming the four *good*
  values) instead of naming the three *bad* ones plus `null`. Both work today,
  but the chosen form — exclude the values `OS_READ_FAILURES` doesn't cover —
  is the one that fails loudly (a fifth good value silently passes an
  inclusion-list check written the other way, but breaks visibly if excluded
  and no story explains why) the moment a new failure kind is added without
  updating this function, which is the failure mode worth optimizing the code
  for.
- Adding the `remediation: unparsed > 0 ? f() : undefined` form instead of the
  spread. Not a bug today, but a maintenance trap: the next reviewer
  diffing findings in a snapshot test now sees a `remediation: undefined` line
  churn in and out depending on test data, instead of the key simply not
  being there.

## Compared to what you know

- **The lookup table replacing the aggregate-plus-condition** is the same
  move as replacing a single `except Exception as e: return "something went
  wrong"` in Python, or one `catch (Exception e)` in Java, with a chain of
  typed catch clauses (or, in modern Java, a `switch` pattern-matching over a
  sealed interface's permitted subtypes) — one handler per concrete failure,
  each with its own recovery action, instead of one handler that has to
  produce a message vague enough to cover everything it might catch.
- **`explainedElsewhere`'s bug** is a scoping mistake any senior engineer will
  recognize from code review in any language: a predicate meant to answer a
  question about *one item* was instead computed over the *whole collection*
  and then applied to every item uniformly. It's the same shape as a stale-
  cache bug where one cache-invalidation flag is shared across all rows
  instead of keyed per row — the fix is always "narrow the scope of the flag
  to match the scope of the thing it's guarding," and it's always easiest to
  miss in exactly the case where the flag *happens* to give the right answer
  for the common, single-failure case tested first.
- **`Record<Exclude<Union, ...>, V>`** maps most directly onto Java's `enum`
  implementing an interface with a method per constant (`switch`-free
  dispatch, compiler-enforced completeness at the `enum` declaration) or a
  Kotlin `sealed class` with a `when` expression the compiler requires to be
  exhaustive. The place the analogy breaks: those languages check
  exhaustiveness as a core language feature at every use site automatically;
  TypeScript's version only checks it *where you explicitly reach for a
  `Record` or turn on the lint rule* — it's an opt-in discipline, not a
  language default, and it's opt-in per construct (the `Record` here, the
  separately-configured lint rule for the `switch`), not a single global
  guarantee.

## Gotchas & idioms

- **`tsc` alone does not enforce switch exhaustiveness.** A `switch` over a
  union that falls off the end with no `default` and no cases for some
  members compiles cleanly under plain `tsc`. This repo's guarantee comes from
  `@typescript-eslint/switch-exhaustiveness-check` in `eslint.config.js:37`,
  which is CI-enforced, not compiler-enforced — removing that one line
  (accidentally, in a config merge) silently turns every exhaustive switch in
  the codebase back into a switch the compiler will never flag for a missing
  case.
- **Narrowing does not cross function-call boundaries.** Discriminating a
  union inside a `switch`/`if` only narrows the *local* variable in that
  scope. Passing the narrowed value into another function does not narrow
  that function's own parameter type — the callee sees the parameter's full
  declared type and, if it needs the narrower guarantee, has to either
  re-establish it (as `unreadableFinding` does, with a guard-and-throw) or the
  call site has to pass the already-narrowed *value* directly rather than the
  whole object it came from.
- **`Exclude<Union, Members>` is a distributive conditional type**, not a
  runtime filter — it computes at the type level only, and produces `never`
  (not an error) if you exclude every member, which would then make a
  `Record<never, V>` an object type requiring no keys at all — worth knowing
  because that's a silent way to accidentally make an "exhaustiveness" table
  optional again.
- **Spreading a conditional array/object literal (`...(cond ? [x] : [])`) is
  this codebase's running idiom for "include this key/element only when a
  condition holds," used identically for evidence array entries and for the
  optional `remediation` field.** Prefer it over `field: cond ? value :
  undefined` when the presence/absence of the key itself is meaningful to a
  reader or a snapshot test, not just its value.
- **`assertRemediable` only requires `remediation` on `blocker`/`degraded`
  findings** (`src/model/finding.ts:94-102`) — an `unknown`-severity finding
  like `truststore.os.unreadable` is not required to carry one by that guard,
  but every one of these four rows carries one anyway, because an operator
  reading "unknown" still needs to know what to do next; the type system and
  the runtime assertion set the floor, not the bar this codebase actually
  writes to.

## Check yourself

1. Walk the exact sequence of finding ids `osFindings` would have produced
   under the *old* code for the two-failure scenario in
   `names the store that failed, distinctly from the one that timed out`
   (one `timeout` store, one `reader-failed` store). Which finding is missing,
   and what boolean's value made it disappear?
2. `OS_READ_FAILURES` is typed `Record<Exclude<TrustStoreFailure,
   'unsupported-platform' | 'timeout' | 'aborted'>, {...}>`. Suppose a future
   change adds an eighth `TrustStoreFailure` member, `'permission-denied'`, to
   `types.ts`, and nothing else in `evaluate.ts` is touched. Does the project
   fail to build, and if so, at which line?
3. `unreadableFinding`'s guard throws if `failure` is `null`, `'timeout'`,
   `'aborted'`, or `'unsupported-platform'`. Could that `throw` ever actually
   execute given how the function is called today? If it can't, why keep it
   instead of an unsafe type assertion (`failure as keyof typeof
   OS_READ_FAILURES`)?
4. `CONFIRM_LISTING_HINT.node` names `NODE_EXTRA_CA_CERTS`. The commit notes
   no real reader sets `TrustSet.partial: true` for Node today. Trace why that
   makes the *old*, wrong hint a defect that shipped invisibly rather than one
   that would have failed a test — and name the one thing that would have to
   change in this codebase for that hint to start actually reaching an
   operator.
5. Rewrite `explainedElsewhere` (the deleted boolean) so that the *old*
   aggregate-based design would have been correct — i.e., scoped per store
   instead of per run — without switching to the new per-store-finding
   design. What does the resulting code look like, and why did the actual fix
   choose to delete the aggregate entirely instead?

<details>
<summary>Answers</summary>

1. Old code: the `timeout` store hits its own unconditional per-store branch
   and produces `truststore.os.read-timeout`. The `reader-failed` store hits
   none of the per-store `if`s (its `failure` is not `null`, `'timeout'`, or
   `'aborted'`), so it falls through to the post-loop aggregate logic. There,
   `osEvidenceLevel(...) === 'none'` is true (both stores unread) and
   `failed.length > 0` is true (the `reader-failed` store is in `failed`), but
   `explainedElsewhere` is also true — because `.some()` found the *other*
   store's `'timeout'` — so the `else if` condition is false and the aggregate
   branch never runs. The `reader-failed` store produces zero findings. The
   missing finding is the aggregate `truststore.os.unreadable`, and the value
   that suppressed it is `explainedElsewhere === true`, computed from a store
   that isn't the one being suppressed.
2. Yes, it fails to build — at the `OS_READ_FAILURES` object literal's
   assignment (`src/probes/truststore/evaluate.ts`, the `const OS_READ_FAILURES:
   Readonly<Record<...>> = { ... }` line). `Exclude<TrustStoreFailure,
   'unsupported-platform' | 'timeout' | 'aborted'>` now includes
   `'permission-denied'`, so `Record<...>` requires a `'permission-denied'`
   key the object literal doesn't have — a "missing property" type error,
   caught at that exact line, not at any call site and not at runtime.
3. No — every call site is the one `switch` case in `osFindings` that only
   reaches `unreadableFinding(store)` after the switch has already matched
   `store.failure` against `'reader-missing' | 'reader-failed' |
   'output-too-large' | 'no-certificates'`, so the guard's condition is
   unreachable given the current call graph (hence the `/* c8 ignore next */`
   suppressing the coverage tool's complaint about an untested branch). It's
   kept instead of `as keyof typeof OS_READ_FAILURES` because a type
   assertion is a claim with zero runtime enforcement — if a future call site
   is added that doesn't go through the switch (a bug, by construction), the
   assertion version silently indexes `OS_READ_FAILURES` with `undefined`
   destructured as `{ title, remediation }`, producing a finding with
   `title: undefined` that fails somewhere far from the actual mistake; the
   `throw` version fails immediately, at the call, naming the actual bad
   value.
4. It's a defect that ships invisibly precisely because nothing exercises the
   `node` + `set.partial` combination in production: `TrustSet.partial` is
   only ever `true` in this codebase where a test fixture sets it directly
   (`runtimeStore('java', { ..., partial: true })` in the new
   `caps a correlated missing-root at degraded` test), and no real Node
   trust-set reader in `src/net/` currently produces a partial read for Node.
   A wrong string that no code path ever renders to an operator cannot fail a
   test that checks rendered output, because no test exercises that render.
   What would have to change: a real Node trust-store reader would need to
   gain a *partial*-read mode — e.g., reading `NODE_EXTRA_CA_CERTS` but hitting
   a size cap or a permission error partway through — the same shape of
   partial outcome the OS and other-runtime readers already support.
5. The minimal per-store fix, keeping the aggregate shape: compute the
   "already explained" set as a `Set<TrustStoreOutcome>` (or filter `failed`
   itself) excluding *that store's own* `timeout`/`aborted` siblings, e.g.
   replace the single array-wide `.some()` with a per-store check inline in
   the `filter` that builds `failed`, so a store already covered by its own
   `readTimeoutFinding`/`aborted` branch is excluded from `failed` by identity
   rather than by "does anything in the array have this failure kind." That
   fixes the scoping bug but keeps every real defect of the aggregate design
   from Decision one: one remediation string still has to cover however many
   distinct root causes happen to remain in `failed` on a given run, and the
   evidence array still flattens N stores' `store`/`failure`/`code` into one
   finding's evidence rather than N findings. The actual fix chose to delete
   the aggregate rather than patch its scoping, because the scoping bug was a
   symptom of the aggregate's core problem (a per-store fact represented in a
   run-wide value), not an independent defect layered on top of an otherwise
   sound design.

</details>

## Further reading

- [`@typescript-eslint/switch-exhaustiveness-check`](https://typescript-eslint.io/rules/switch-exhaustiveness-check/)
  — the rule doc, including its `requireDefaultForNonUnion` and
  `considerDefaultExhaustiveForUnions` options this repo does not enable.
- [TypeScript Handbook — Narrowing](https://www.typescriptlang.org/docs/handbook/2/narrowing.html)
  — control-flow narrowing, including why it's scoped to the function it
  happens in.
- [TypeScript Handbook — `Exclude<Type, ExcludedUnion>`](https://www.typescriptlang.org/docs/handbook/utility-types.html#excludetype-excludedunion)
  and the [conditional types chapter](https://www.typescriptlang.org/docs/handbook/2/conditional-types.html#distributive-conditional-types)
  it's built from.
- [The Rust Book — enums and pattern matching](https://doc.rust-lang.org/book/ch06-00-enums.html)
  and [`match` exhaustiveness](https://doc.rust-lang.org/book/ch06-02-match.html#matches-are-exhaustive)
  — the compiler-native version of the guarantee this diff builds out of a
  lint rule plus two utility types.
