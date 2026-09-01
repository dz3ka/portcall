# ADR-0046: The demo is a real check against the harness, and it must exit 2

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

M5 makes this repo public. The thing a reader is asked to believe is the claim
on the tin: portcall walks into a network it does not own and names exactly what
is blocking a rollout. Every other artefact in the repo argues that claim -
ADRs, a fixture suite, a hostile-network harness - and none of them lets a
reader *see* it in one step. `test/harness/README.md` documented four
`docker compose` commands, and the fourth ran `vitest`. A recorded terminal of
vitest printing seven green ticks demonstrates that somebody's tests pass. It
does not demonstrate the product.

The harness (SPEC.md §10, ADR-0025) already plants everything the demo needs: a
split-horizon resolver, an origin under a CA nobody ships, a proxy re-signing
TLS with a root it generated, a proxy demanding Basic auth, a proxy that will
not tunnel a non-443 CONNECT, and - since ADR-0041 - a root that the container's
*OS* trusts while node's bundle does not. What was missing was a command that
runs `portcall check` against it and shows the report.

Three things make that non-obvious enough to record.

**The pass condition is inverted.** Every other command in this repo passes by
exiting 0. A demo of this network that exits 0 is broken: it means the planted
conditions never reached the probes. The interesting exit code is 2 - ADR-0006's
`blocker` - and it has to be asserted, or the demo degrades silently into a
recording of portcall shrugging at a network that is on fire. The failure mode
is specific: `up --wait` succeeds, the container starts, some plumbing detail
means `HTTPS_PROXY` is never seen or the OS store never planted, and the report
is a wall of `ok`. Nothing about that looks like a failure to a script checking
for zero.

**The demo needs a profile, and the suite already had one.** `portcall check`
takes `--profile`, and the profile decides which hosts get contacted at all
(SPEC.md §4, non-negotiable 3). The integration suite's `harnessProfile()` was
already exactly the right profile - two real public hostnames, one required on
443 and one optional on 8080, `runtimes: [node]`, `interception_tolerated:
false` - but it was a TypeScript function, unreachable from a CLI that reads
YAML. The obvious move is to write the YAML the CLI needs and leave the function
alone. That produces two definitions of one profile and a reason to write a test
asserting they stay equal.

**The subnet is hard-coded.** `10.31.0.0/24` is fixed in `docker-compose.yml`
and repeated as literal addresses in `dns/dnsmasq.conf`, which is what lets a
reader check the two files against each other. On a machine already using that
range, `docker compose up` fails.

## Decision

**`npm run demo` runs a real `portcall check` inside the harness and requires it
to exit 2. The harness profile becomes a YAML file the demo passes to the CLI,
and the integration suite parses that same file.**

Concretely:

1. `scripts/demo.mjs` runs the four documented compose commands in order -
   `up --wait`, `build portcall`, `run --rm`, `down -v --remove-orphans` - with
   the run step executing `node src/cli/index.ts check --profile
   test/harness/demo-profile.yaml --format text` behind
   `HTTPS_PROXY=http://mitmproxy:8080`, instead of the service's own
   `npm run test:integration`. The entrypoint is deliberately not overridden: it
   is what plants mitmproxy's root in the container's OS store (ADR-0041).
2. **Any exit code other than 2 fails the script**, with a message that reads 0
   and 1 as "a planted condition did not reach the probes" and 3 as "portcall
   itself failed", because those are two different tickets.
3. Teardown runs on every path - a failed `up`, a wrong exit code, an unexpected
   throw - and never replaces the failure that got there, so a real error is
   never repainted as a Docker problem.
4. `test/harness/demo-profile.yaml` is the **single** definition of the harness
   profile, and `harnessProfile()` in `test/integration/harness.ts` parses it
   with the product's own `parseProfile`. The comments that argued the profile's
   contents - why the hosts are real public names, why `interception_tolerated`
   is `false` - move into the YAML, beside what they explain.
5. The subnet stays hard-coded. A non-zero `up --wait` prints one line naming
   `10.31.0.0/24` and pointing at the harness README's limitations section.

## Alternatives considered

**Keep `harnessProfile()` and add the YAML beside it, with a test asserting they
match.** Rejected, and this is the sharpest call here. The test would have been
real - `expect(parseProfile(yaml).profile).toEqual(harnessProfile().profile)` -
and it would have caught the drift. But the drift is one this change would have
*introduced*: there is no second definition today, and the only argument for
adding one is that the CLI reads YAML while the suite reads TypeScript. Parsing
the YAML in the suite costs three lines, uses the loader the product already
ships, and makes the equality unfalsifiable rather than merely tested. Machinery
that guards a duplication the same commit creates is a design smell, not
diligence; the smaller design is the one where the file cannot disagree with
itself. The consequence is that `demo-profile.yaml` is now exercised by every
harness run rather than only when somebody records a demo, which is strictly
better than a test that only proves two copies are still copies.

**Put the profile in `profiles/` instead.** Rejected. `profiles/*.yaml` is
shipped surface: `scripts/embed-profiles.mjs` bakes every file there into the
binary, `portcall profiles` lists them, and ADR-0043 records that a filename in
that directory is public CLI vocabulary. A harness fixture pointing two real
public hostnames at RFC1918 addresses has no business being offered to a
customer by name.

**A `--dry-run` flag on `scripts/demo.mjs`.** Rejected. `build-binaries.mjs`
earns its `--dry-run` because compiling five targets needs bun, which most
machines do not have, so the plan is the only thing checkable locally.
`docker compose` is neither expensive to attempt nor impossible to run, and the
"plan" the flag would print is the four-command table already in
`test/harness/README.md`. It is a flag nothing toggles and no test would cover.

**Preflight the subnet by parsing `docker network inspect` IPAM.** Rejected.
`docker compose up` already fails on overlap with "Pool overlaps with other one
on this address space", which is an accurate and searchable message. Replacing
it would mean walking untyped JSON across daemon versions - new code with new
failure modes - to improve one string. The script adds the one thing compose
cannot know: which range *this* project wants, and where the limitation is
written down.

**Make the subnet configurable.** Rejected for a boring reason: the addresses
are also literals in `dns/dnsmasq.conf`, so a configurable subnet means
templating the DNS zone at container start. That is real machinery for a
collision that is rare, loud, and one `docker network` command away from being
fixed by hand.

**Detect host-route and VPN collisions too.** Rejected as undetectable without
platform-specific commands - and SPEC.md §4 keeps this tool out of the business
of interrogating a machine it was not asked to interrogate. It is documented as
a known limitation instead, with its symptom stated (services that come up and
then cannot reach each other) rather than guessed at.

**Assert on the report's contents, not just the exit code.** Rejected as
duplication. `test/integration/tls-harness.test.ts` already asserts the ids,
severities and evidence of every planted condition, in the same network, on the
same profile. The demo's job is to be watchable; its one machine-checkable
claim is the verdict, and the verdict is the exit code.

## Consequences

- A reader gets the claim in one command: `npm run demo`. The recording WP4
  produces is of the product, not of a test runner.
- **The demo is now a check on the harness itself.** If a future edit breaks the
  interception plant or the OS-store plant, the demo goes red rather than
  quietly recording a boring report - the same reason ADR-0025 refuses to let
  the suite skip when the network is absent.
- Exit 2 as a pass condition is unusual enough to be surprising in a CI log. It
  is stated in the script's header comment, in the failure message, and in the
  harness README, because a reader who has not seen ADR-0006 will otherwise read
  the demo job as broken.
- `harnessProfile()` now touches the filesystem, where it used to be a pure
  constructor. It reads one file relative to its own module URL, never the cwd.
  A malformed `demo-profile.yaml` now fails the integration suite at the profile
  rather than at the first assertion - which is the product's own failure mode,
  and better than a hand-built object that could never be malformed.
- Ctrl-C is the one path that does not tear down: it kills the script along with
  the compose command it is waiting on. A signal handler was not added - it
  would be new machinery for a case the README can state in three lines, and the
  cleanup is one command. It is under "Known limitations".
- `demo:record` is defined as `vhs demo/portcall-demo.tape` and is inert until
  the tape lands. `vhs` is not a repo dependency and is not installed by
  anything here; it is a recording tool a human or a CI job brings.
