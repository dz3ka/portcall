# Lesson 0001: A check that never ran, and a claim that was never true

- **Date:** 2026-08-27
- **Commits:** `870486b`, `c1e0575`, `c06c8c4`
- **Records:** [ADR-0030](../adr/0030-the-harness-zone-is-ipv4-only-and-aaaa-is-unanswered.md),
  [ADR-0031](../adr/0031-cross-runtime-parity-is-a-verdict-claim-not-a-bundle-claim.md)

## What we built

M3 shipped the `tls` probe: chain capture through a proxy, an interception
verdict, and a `docker compose` hostile-network harness that CLAUDE.md calls "a
first-class deliverable, not a test util". The milestone was then declared
complete. It was not complete. CI was red on the very commit that declared it,
and the harness — the deliverable the milestone was sold on — had never once
executed, in CI or on a laptop.

This goal fixed both and nothing else. No probe changed, no finding id moved, no
fixture was re-recorded. Three commits: one flag added to a compose healthcheck
(`870486b`), one test assertion replaced with a different assertion over the same
subject (`c1e0575`), and one pass over the prose that the first two falsified
(`c06c8c4`). The net effect on a customer running the binary is exactly zero,
which is worth saying out loud, because the value of the goal is entirely in what
is now *known* rather than in what the software now *does*.

The two failures look unrelated — a DNS query type and a certificate-bundle
comparison — and they are the same failure. In both cases the code was fine and
the **claim** was wrong. A healthcheck asserted more than the system it guarded
had ever promised, so it failed on a healthy system. A test asserted a property
the project never promised and could never hold, and cited an ADR that says
something else entirely. Neither is a bug you find by reading the
implementation, because in both cases the implementation is correct. You find
them by reading the assertion and asking: *who signed up for this?*

## The design decision

### Decision one: fix the check, not the system it checks

The `dns` service in `test/harness/docker-compose.yml` plants split-horizon DNS —
real public names (`api.anthropic.com`) answering with an RFC1918 address inside
the harness network. Its healthcheck was `nslookup api.anthropic.com 127.0.0.1`.
The image is Alpine, so that `nslookup` is BusyBox's, and BusyBox with no `-type`
issues **an A query and an AAAA query** and exits non-zero if either leg fails.
`dnsmasq.conf` plants A records and nothing else, so the AAAA leg came back
`REFUSED`. The container printed the correct answer `10.31.0.20`, then printed
`REFUSED`, then exited 1. Fifteen retries of a correct answer later the service
was `unhealthy`, and because four other services declare
`depends_on: dns: {condition: service_healthy}`
(`test/harness/docker-compose.yml:85`, `:114`, `:157`), `up --wait` tore the
whole network down.

The fix is `-type=a` (`test/harness/docker-compose.yml:49`). Zero DNS records
changed, so the network ADR-0025 described is byte-for-byte the network that now
boots. Three alternatives were rejected, and the reasons are the interesting
part:

- **Plant an AAAA (`address=/api.anthropic.com/::`).** The symmetric fix, and the
  worst one. It makes the resolver return a *real, wrong* v6 answer that the
  `dns` probe would be correct to treat as a genuine answer. A harness exists to
  plant conditions the code under test can detect; this plants a condition that
  lies to it undetectably. **The rule: never make a test fixture more capable
  than the thing it stands in for.**
- **`filter-AAAA`** (turn REFUSED into an empty NODATA, which is how real v4-only
  networks behave). Rejected *on evidence, not taste*: nobody had measured
  BusyBox's exit status on NODATA. Fixing a never-executed check with a change
  whose effect on that check is unmeasured is how you get a second silent
  failure. The `-type=a` behaviour was measured in the same minute.
- **`pidof dnsmasq` or a TCP connect to :53.** Would have gone green
  immediately, and is a direct violation of ADR-0025: dnsmasq binds its socket
  long before a bad config would be noticed, so process liveness passes for a
  resolver serving an empty zone. **The fix for a too-strict check is not a check
  that proves nothing.**

The second half of the decision costs nothing and matters more than the flag: the
IPv4-only zone is now *written down as deliberate*
(`test/harness/dns/dnsmasq.conf:19-30`). The file's own header had claimed "every
answer below is an answer this file put there... a plant rather than an
accident". For AAAA that sentence was false. The pattern here is **executable
intent**: a healthcheck is a machine-readable statement of what "working" means,
and when it disagrees with the system, one of the two is wrong and you have to
say which before you touch either.

### Decision two: assert the verdict, not the artifact

`test/net-root-bundle.test.ts` asserted that Node and bun ship **byte-identical
public-root bundles**, and cited ADR-0002 as its authority. Once ADR-0025 put bun
on the `verify` job of all three runners, the test stopped skipping and went red
on ubuntu, macOS and Windows alike — one failing test out of ~682 on each.

Three separate things were wrong, and they are worth pulling apart because the
first read of the failure gets it backwards:

1. **The assertion cannot be made true.** CI's Node 22 ships 145 roots, bun ships
   121, this machine's Node 24 ships 120. The list is a snapshot of Mozilla's CA
   program taken whenever each runtime cut a release; it diverges Node-to-Node as
   readily as Node-to-bun. A green version of this test would be an accident of
   two release dates lining up, and would go red on the next Node bump.
2. **The citation was the defect, not the ADR.** ADR-0002 never promised
   identical bundles. What it says is that the evaluation must not read the
   *runtime's certificate objects* (`tls.PeerCertificate`, `node:crypto`'s
   `X509Certificate`), because then the answer depends on which runtime ran.
   `src/net/root-bundle.ts` honours that — it re-exports PEM strings, plain data,
   and portcall parses them itself. The falsified claim lived in two code
   comments that cited an ADR for something it never said. That is why ADR-0031
   *cites* ADR-0002 and ADR-0025 rather than superseding either: nothing was
   decided wrongly, something was described wrongly.
3. **The claim that mattered was measured by nothing.** The old test hashed PEM
   strings with `node:crypto`. Not one line of `publicRootIndex` or
   `classifyRoot` — `src/probes/tls/public-roots.ts:106` and `:179`, the code
   that decides `tls.public-root` versus `tls.private-root` — had ever executed
   under bun, which is the runtime that compiles the binary a customer runs
   (ADR-0001). A test can be red, expensive to maintain, and still be covering
   nothing you care about.

The replacement asserts the **verdict** over a **pinned input**:
`test/fixtures/tls/root-verdicts.ts` builds a reference root set out of the
anchors the *committed* fixture chains present, runs portcall's own evaluation
over every committed capture (direct and via-proxy), and emits the whole
`RootVerdict` — class, reason, `matchedIndex`, `path`. The Node-side test imports
that module and runs it in-process; `print-root-verdicts.ts` runs the same module
under bun and prints one line of JSON; the test deep-compares. **One
implementation, measured twice.** Pinning the input is what makes the comparison
possible at all: two runtimes classifying two different root lists cannot be
compared even in principle.

One bundle claim survives, narrowed to exactly the difference that reaches a
customer: each root the fixtures anchor in must be present in *both* runtimes'
own bundles (`fixtureAnchorsInRuntimeBundle`, `root-verdicts.ts:128`). A root in
one list and not the other flips `tls.public-root` to `tls.private-root` for the
same network. Bundle *size* differing by twenty-five roots flips nothing until
one of those roots is the one in front of you.

Rejected, from ADR-0031: vendoring a root bundle into the repo (a stale copy
calls a genuine public root "private" — the most alarming finding this tool
emits, produced on a healthy network); downloading Mozilla's list at test time
(SPEC.md §4 forbids network calls off-profile, and a suite that fetches is a
suite that fails on the air-gapped laptop this tool exists for); asserting the
intersection exceeds some threshold (arbitrary across 145/121/120, and still
executes none of portcall's own code under bun — the same brittleness in a
costume); deleting the case (leaves the shipped binary's evaluation path executed
by nothing, anywhere).

The general form, and the thing to carry out of this repo: **assert the behaviour
you sell, over inputs you control; do not assert the shape of an artifact you do
not own.** The bundle is someone else's release artifact. The verdict is yours.

## Code deep-dive

This repo is TypeScript, so there is no Go/Rust idiom lesson here. What follows
is a walk through the four snippets where the *verification* reasoning is
encoded, plus the two places the type system is doing real work.

### 1. The healthcheck that asserts exactly what the zone promises

```yaml
    healthcheck:
      # Resolves the planted name, not just "is the process up": dnsmasq answers
      # on the socket well before a bad config would have been noticed otherwise.
      # `-type=a` is load-bearing - do not "simplify" it away. BusyBox `nslookup`
      # with no type asks A *and* AAAA, and this zone is planted IPv4-only by
      # design (dns/dnsmasq.conf), so the AAAA half is answered REFUSED and
      # BusyBox exits 1 having just printed the correct A answer. Without the
      # flag this service is unhealthy forever and `up --wait` aborts the network.
      test: ['CMD', 'nslookup', '-type=a', 'api.anthropic.com', '127.0.0.1']
      interval: 2s
      timeout: 3s
      retries: 15
      start_period: 5s
```

`test/harness/docker-compose.yml:40-53`

Read the check as a predicate and ask what it quantifies over. The old one was
"for every address family, this name resolves" — universally quantified over a
set the zone never made promises about. The new one is "the A record for this
planted name answers" — quantified over exactly the set `dnsmasq.conf` plants.

Two form details are load-bearing. `CMD` (not `CMD-SHELL`) means Docker execs the
argv array directly with no shell in between, so there is no `sh -c` to swallow
or transform the exit status — the check's verdict *is* BusyBox's exit code. And
`start_period: 5s` versus `retries: 15` do different jobs: failures inside the
start period do not count against the retry budget, so the retry count is about a
service that has failed to converge, not about a service that has not booted yet.
A newcomer's instinct is to raise `retries` when a healthcheck flaps; here that
would have bought fifteen more identical correct answers followed by the same
abort.

The comment is longer than the line it guards, deliberately. `-type=a` reads like
noise, and the failure mode of deleting it is not "a test goes red" — it is
"`up --wait` hangs and then the whole network aborts on a network that works".
That failure is expensive to re-diagnose and cheap to prevent with six lines of
prose.

### 2. Building a reference set out of committed bytes — and refusing to guess

```ts
export const FIXTURE_ROOT_PEMS: readonly string[] = fixtureRootPems();

function fixtureRootPems(): string[] {
  /** Keyed by subject so a root shared by several fixtures - all four share ISRG Root X1 - is indexed once. */
  const anchors = new Map<string, string>();

  for (const condition of RECORDED_CONDITIONS) {
    const fixture = loadRecordedChain(condition);
    if (fixture.publicAnchor === null) continue;

    const der = fixture.direct.chainDer.at(-1);
    if (der === undefined) throw new Error(`${condition}: recorded chain is empty`);
    const anchor = new X509Certificate(der);
    if (anchor.subject !== fixture.publicAnchor) {
      throw new Error(`${condition}: last certificate is ${anchor.subject}, not the recorded anchor ${fixture.publicAnchor}`);
    }
    anchors.set(anchor.subject, anchor.toString('pem'));
  }

  if (anchors.size === 0) throw new Error('no recorded chain carries a public anchor');
  return [...anchors.values()];
}
```

`test/fixtures/tls/root-verdicts.ts:44-65`

The whole point of this function is that its output is a function of **committed
bytes only**. Taking `PUBLIC_ROOT_CA_PEMS` here would put the thing under test on
both sides of the comparison and quietly reintroduce the unfixable assertion —
the two runtimes would once again be compared against two different root lists.

Three defensive moves worth naming:

- `.at(-1)` returns `T | undefined` under this repo's strictness settings, and
  the code narrows it with an explicit `throw` rather than a non-null assertion.
  In a fixture builder, `!` would turn "somebody committed an empty chain" into a
  `TypeError` fifteen frames away inside `@peculiar/x509`.
- The `anchor.subject !== fixture.publicAnchor` check is a **cross-check between
  two independently recorded facts**: the DER bytes and the JSON metadata beside
  them. Either can rot on its own; neither can rot silently while the other
  agrees. This is the same discipline as `dnsmasq.conf` duplicating the static
  `ipv4_address` assignments so a reader can check them against each other.
- `if (anchors.size === 0) throw` is the anti-vacuity guard. Without it, a
  fixture set that lost its `publicAnchor` metadata would produce an empty root
  index, every chain would classify as `private` under both runtimes, the deep
  compare would pass, and the test would be green while measuring nothing. **The
  most dangerous state for a verification suite is not "wrong", it is "empty".**

`Map` keyed by subject is doing deduplication: all four recorded chains currently
anchor in ISRG Root X1, so the reference set has one entry. ADR-0031 states that
limit plainly instead of implying breadth the fixtures do not have.

### 3. Shipping the whole verdict across a process boundary

```ts
/** One verdict, flattened to JSON-safe scalars so it survives the trip out of a Bun subprocess unchanged. */
export interface CrossRuntimeVerdict {
  readonly condition: RecordedCondition;
  readonly connection: Connection;
  readonly class: RootClass;
  readonly reason: RootReason;
  readonly matchedIndex: number | null;
  readonly path: readonly number[];
}
```

`test/fixtures/tls/root-verdicts.ts:68-75`

Every field is a string, a number, `null`, or an array of numbers. That is not
tidiness; it is the contract of the transport. The comparison travels through
`JSON.stringify` in the bun child and `JSON.parse` in the Node parent, and JSON
is lossy in ways that would silently weaken the assertion: `undefined` fields
vanish from an object entirely (so `{a: undefined}` and `{}` become
indistinguishable), `Map` and `Set` serialise to `{}`, `Uint8Array` serialises to
an object with numeric string keys, `Date` becomes a string that does not
round-trip back to a `Date`. Any of those would produce a comparison that passes
for the wrong reason. Flattening to scalars at the boundary makes "these two JSON
documents are equal" mean "these two evaluations agreed".

`matchedIndex: number | null` rather than `number | undefined` is the same
concern: `null` survives JSON, `undefined` does not.

And note *what* travels: not just `class`, but `reason`, `matchedIndex` and
`path`. A runtime that agreed the chain is `public` while disagreeing about which
index matched, or about the issuance path, would have a genuine divergence in
`canonicalDn` (`src/probes/tls/public-roots.ts:93`) or in the issuance walk —
exactly what a `String.prototype.normalize` or base64 difference between two JS
engines produces. Asserting only the coarse answer would let a real engine
difference through as long as it happened not to change the label. **Compare the
richest observation you have, not the summary of it.**

### 4. The parity test, and its two guards against passing for free

```ts
describe('root verdicts under bun and under node', () => {
  it.skipIf(BUN === null)('reach the same answer over the same fixture chains (ADR-0031 parity)', () => {
    const printed = spawnSync('bun', [PRINTER], { encoding: 'utf8' });
    expect(printed.status, `bun exited ${String(printed.status)}: ${printed.stderr}`).toBe(0);

    const parsed = JSON.parse(printed.stdout.trim()) as CrossRuntimeReport;

    // The verdicts are portcall's own evaluation, run twice over pinned input.
    expect(parsed.verdicts).toEqual(fixtureVerdicts());

    // ...
    const anchors = fixtureAnchorsInRuntimeBundle();
    expect(Object.keys(parsed.anchorsInRuntimeBundle).sort()).toEqual(Object.keys(anchors).sort());

    for (const [subject, bundled] of Object.entries(parsed.anchorsInRuntimeBundle)) {
      expect(bundled, `${subject} is not in bun ${BUN ?? ''}'s root bundle`).toBe(true);
    }
```

`test/net-root-bundle.test.ts:73-95`

`expect(printed.status, ...).toBe(0)` comes **first**, with `stderr` in the
message. If the bun child dies on an import error, `printed.stdout` is `''`,
`JSON.parse('')` throws `SyntaxError: Unexpected end of JSON input`, and you
spend twenty minutes wondering what is wrong with the JSON. Asserting the exit
status first converts that into "bun exited 1: <the actual stack>". Vitest's
second argument to `expect` is the failure message — cheap, and it is the
difference between a diagnosable CI log and a puzzle.

`JSON.parse(...) as CrossRuntimeReport` is an **unchecked type assertion**, and
this repo uses zod elsewhere precisely to avoid those. It is defensible here, but
only because of what follows it, and it is worth being explicit about why rather
than waving at "it's a test". `parsed.verdicts` is immediately deep-compared
against a locally computed array, so `undefined` or a wrong shape fails loudly on
the next line. `parsed.anchorsInRuntimeBundle` is the risky one:
`Object.entries({})` is `[]`, so the `for` loop over an empty object executes
zero assertions and **passes**. That is what the key-set comparison on the line
above it exists for — it forces the parsed object to have exactly the subjects
Node found before the loop is allowed to be the proof. If you take one habit from
this file, take that one: **whenever an assertion lives inside a loop, ask what
happens when the loop body never runs, and assert the cardinality separately.**

`it.skipIf(BUN === null)` is deliberate and is *not* the smell it looks like.
Portcall's whole distribution argument (ADR-0001) is that it runs on a
locked-down machine where nothing is installed; a suite that hard-requires bun
fails on exactly the class of machine the tool is built for. But a skip is a
weaker guarantee than a pass, so the gate is paired with two things: a loud
`console.info` at module load stating in words that the check is **SKIPPED, not
passed** (`test/net-root-bundle.test.ts:41-47`), and ADR-0025's decision to
install bun on the `verify` job of all three runners
(`.github/workflows/ci.yml:30-38`) so the claim executes *somewhere* on every
push. CLAUDE.md forbids closing a milestone with a skipped test because a
conditional skip in CI is a permanent green lie; the resolution is not to delete
the gate, it is to make sure the environment that skips is never CI.

## What would break

**The failure modes now handled:**

- A dnsmasq config error that leaves the zone empty. The healthcheck resolves the
  *planted name* and requires an answer, so an empty zone is unhealthy.
  `pidof dnsmasq` would have called it healthy.
- A future engine difference in `canonicalDn`, the issuance walk, base64
  decoding, or Unicode normalisation between Node and bun. The full-verdict
  comparison catches it; the old fingerprint comparison could not have, because
  it never ran portcall's code under bun at all.
- A runtime that drops a root the fixtures anchor in. It fails by name
  (`ISRG Root X1 is not in bun 1.x's root bundle`) rather than as an opaque count
  mismatch.
- Fixture rot: DER that disagrees with the recorded `publicAnchor`, an empty
  chain, or a fixture set with no public anchor at all, each with its own
  message.

**The failure modes still open, stated because ADR-0030 and ADR-0031 state
them:**

- The `dns` healthcheck is now blind to the family it stopped asking about.
  Acceptable because the zone has no v6 content to be wrong about. glibc's
  `getaddrinfo` drops the refused AAAA leg silently and every container in the
  harness is glibc today; musl is under no such obligation, and a future Alpine
  service would see a resolution failure whose symptom has nothing to do with the
  condition it plants. **A comment is a warning, not a guard** — the ADR says so,
  and names the fix to reach for when that day comes (`filter-AAAA`, measured
  first).
- The anchor claim is exactly as wide as the fixture set: one root. A fixture
  anchored elsewhere widens it for free.
- The harness is green on a local Docker daemon, warm and from a cold `down -v`.
  The README says that and no more, because at the time it was written it had not
  yet been observed green on a hosted runner.

**The bugs a newcomer writes here:**

- "The healthcheck is flaky, raise `retries`." Fifteen more correct answers, same
  abort. When a check fails deterministically and instantly, the retry budget is
  not the variable.
- "The healthcheck is flaky, use `CMD-SHELL ... || true`." Now the service is
  always healthy and four dependents start against a resolver that may be serving
  nothing.
- "The bundles differ, pin the Node version." Node 22 and Node 24 differ from
  each other; pinning buys a green run until the next release re-cuts the
  snapshot.
- "The test is red and its claim is not what we meant — delete it." That leaves
  the shipped binary's entire root-evaluation path executed by nothing, anywhere,
  which is the state ADR-0025 spent a CI job to escape.
- "`JSON.parse` then loop and assert." Passes vacuously on `{}`.

## Compared to what you know

- **The healthcheck is a Kubernetes readiness probe, and the same taxonomy
  applies.** `pidof dnsmasq` is a liveness probe wearing a readiness probe's hat:
  it answers "is the process up", not "will a dependent get a correct answer".
  `depends_on: {condition: service_healthy}` is compose's readiness-gate
  equivalent, and it fans out the same way — one never-ready dependency takes the
  deployment with it. Where the analogy breaks: k8s keeps retrying forever and
  reports `0/1 Ready`, while `compose up --wait` exhausts `retries` and *aborts
  the whole network*, which is why this failed as a hang-then-teardown rather
  than a partially-up environment you could poke at.
- **The parity test is consumer-driven contract testing** (Pact, Spring Cloud
  Contract). The old test asserted the *provider's* internal state — the size and
  content of a bundle owned by the Node and bun release teams. The new one
  asserts the *interaction*: given this input, both implementations produce this
  output. Where it breaks down: in Pact the two sides are two services with two
  codebases; here it is genuinely the same source file executed by two engines,
  so any difference is an engine difference and never a version-skew artifact.
- **`spawnSync` plus JSON on stdout is approval testing across a process
  boundary** — closest to running the same JUnit suite under two JDKs, or the
  same `pytest` under CPython and PyPy. The difference is that the "golden file"
  is not committed: it is recomputed in-process on the Node side every run, so
  there is no snapshot to go stale and no `--update-snapshots` escape hatch that
  launders a real regression into an accepted diff.
- **`it.skipIf` is JUnit's `Assumptions.assumeTrue` / pytest's
  `@pytest.mark.skipif`**, and carries the same hazard: a suite where assumptions
  do the work reports green for a run that verified nothing. The mitigation is
  the same one mature suites use — make the environment that cannot run the check
  *not be CI*.
- **The `as CrossRuntimeReport` cast is Java's unchecked cast from `Object` or
  Python's `typing.cast()`** — a compile-time-only claim with zero runtime
  enforcement. TypeScript's types are fully erased; nothing at runtime checks
  that shape. The discipline that makes it acceptable is that every field is
  asserted immediately afterwards, which is not a property the type system can
  give you.

## Gotchas & idioms

- **`Object.entries(x)` on `{}` is `[]`, and a `for` loop over `[]` passes every
  assertion inside it.** Assert cardinality outside the loop. Same for
  `Array.prototype.every`, which is `true` on an empty array — a "for all"
  assertion is only as strong as the proof that the domain is non-empty.
- **JSON is a lossy transport for a test comparison.** `undefined` disappears (so
  a missing key and an explicit `undefined` compare equal), `Map`/`Set` become
  `{}`, typed arrays become numeric-keyed objects. Design the DTO to be
  JSON-total, and prefer `null` over `undefined` for absent values that must
  cross the wire.
- **`spawnSync` returns a result object, not a throw.** `error` is set for
  spawn-level failures (ENOENT), `status` for a process that ran and exited
  non-zero; `status` is `null` when the child was killed by a signal — which is
  why `String(printed.status)` appears in the message rather than a bare
  interpolation of a possibly-`null` number.
- **`.at(-1)` returns `T | undefined`.** Narrow it with a `throw` that names the
  fixture; do not reach for `!`.
- **`readonly` on an interface field and `readonly T[]` are compile-time only.**
  `FIXTURE_ROOT_PEMS: readonly string[]` prevents `push` at the type level and
  nothing at runtime; it documents intent to the next reader, which is its actual
  job here.
- **`CMD` vs `CMD-SHELL` in a compose healthcheck** changes who owns the exit
  status. `CMD` is a direct exec with no shell; `CMD-SHELL` wraps in `sh -c`,
  where a trailing `|| true` or a pipeline silently changes the verdict.
- **BusyBox `nslookup` is not GNU/BIND `nslookup`.** Untyped, it asks A and AAAA
  and fails if either leg fails. Alpine images have BusyBox. This is the kind of
  detail that makes "it works in my container" untransferable.
- **`tls.rootCertificates` is a snapshot, not a standard.** It is whatever
  Mozilla list the runtime vendored at release time. Treat it as an input you
  read, never as a value you assert.

## Check yourself

1. The `dns` healthcheck now passes `-type=a`. Name a change to `dnsmasq.conf`
   that would break the harness for real and that this healthcheck would **not**
   catch. Is that acceptable, and where is it written down?
2. Suppose `print-root-verdicts.ts` were changed to print
   `{"verdicts": [], "anchorsInRuntimeBundle": {}}`. Walk
   `test/net-root-bundle.test.ts:73-95` line by line: which assertion fails
   first, and which one would have let it through if it were removed?
3. `FIXTURE_ROOT_PEMS` is built from committed fixture bytes rather than from
   `PUBLIC_ROOT_CA_PEMS`. Give the concrete sequence of events by which using
   `PUBLIC_ROOT_CA_PEMS` there would make the parity test pass while proving
   nothing.
4. `it.skipIf(BUN === null)` is allowed, but CLAUDE.md forbids closing a
   milestone with a skipped test. Reconcile those two sentences using ADR-0001
   and ADR-0025. What single change to `.github/workflows/ci.yml` would turn the
   gate back into a green lie?
5. The verdict DTO carries `path: readonly number[]` and
   `matchedIndex: number | null` in addition to `class`. Construct a hypothetical
   engine difference between Node and bun that changes `path` but not `class`,
   and say what real-world misreport it would eventually cause.

<details>
<summary>Answers</summary>

1. Adding an AAAA record — `address=/api.anthropic.com/::` — or any change to a
   name other than `api.anthropic.com` (the `host-record` service names, or
   `registry.npmjs.org`). The check quantifies over one name and one family.
   Acceptable, and it is written down twice: `dnsmasq.conf:19-30` and ADR-0030's
   Consequences, which states the check "is narrower than it reads" and names
   musl as the case that will eventually force a revisit.
2. `expect(parsed.verdicts).toEqual(fixtureVerdicts())` fails first, because
   `fixtureVerdicts()` is non-empty (the fixtures carry an anchor and
   `fixtureRootPems` throws if none do). The vacuous path is the
   `anchorsInRuntimeBundle` loop: `Object.entries({})` is `[]`, so with the
   key-set comparison on line 88 removed, an empty object would satisfy both
   `for` loops and prove nothing about either bundle.
3. Node computes its reference set from Node's 120-or-145-root bundle; the bun
   child computes *its* reference set from bun's 121-root bundle. The two
   processes are now classifying against different root indexes, so the verdicts
   are not comparable — and if every fixture chain happens to anchor in a root
   both bundles carry, the verdicts match anyway and the test goes green. It
   would then go red the moment a fixture anchored in a root only one runtime
   ships, i.e. it reintroduces the exact bundle-identity assertion ADR-0031
   retired, in a form that is harder to see.
4. The gate is about the *environment*, not about the claim: ADR-0001 says the
   tool must run where nothing is installed, so the suite must not hard-require
   bun on a bare laptop. ADR-0025 answers the "then it is measured nowhere"
   objection by installing bun on the `verify` job of all three runners, so CI
   never takes the skip. Removing the `oven-sh/setup-bun` step from `verify`
   (`.github/workflows/ci.yml:38`) makes every runner skip, and the suite reports
   green having measured the project's central claim zero times.
5. Any difference that changes which certificate in the chain is treated as the
   terminus, or how issuer/subject DNs canonicalise — e.g. two engines
   normalising a DN's non-ASCII organisation name differently, so one walks the
   issuance path one link further before matching. `class` stays `public` because
   the same root is eventually matched, but `path` differs. The real-world
   consequence surfaces on a chain where the divergence changes *whether* the
   bundled root is on the leaf's issuance path (ADR-0026) — at which point one
   binary reports `tls.public-root` and the other reports `tls.private-root` for
   the same corporate proxy, which is the exact divergence the project is sold on
   not having.

</details>

## Further reading

- [Compose file reference — `healthcheck`](https://docs.docker.com/reference/compose-file/services/#healthcheck)
  — `test`, `CMD` vs `CMD-SHELL`, and how `start_period` interacts with
  `retries`.
- [Compose — control startup and shutdown order](https://docs.docker.com/compose/how-tos/startup-order/)
  — `depends_on` with `condition: service_healthy`, and why a never-healthy
  dependency aborts rather than degrades.
- [Node.js — `tls.rootCertificates`](https://nodejs.org/api/tls.html#tlsrootcertificates)
  — the API docs say in one sentence that this is the bundled Mozilla snapshot,
  which is the whole reason the old assertion could never hold.
- [Vitest — `test.skipIf`](https://vitest.dev/api/#test-skipif) and
  [Vitest — `expect`](https://vitest.dev/api/expect.html) (the optional message
  argument) — the two APIs that make a conditional check honest about what it
  did.
