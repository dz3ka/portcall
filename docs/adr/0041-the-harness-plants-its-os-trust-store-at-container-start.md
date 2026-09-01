# ADR-0041: The harness plants its OS trust store at container start, and stays a Node-only profile

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

M4's headline behaviour is a correlation: a root the *machine* trusts that a
*runtime* does not, promoted from `degraded` to `blocker` when the TLS probe has
seen that same root terminating an intercepted chain
(`src/probes/truststore/evaluate.ts:637-658` correlates, `:767` promotes). The
hostile-network harness already plants the interception half — `mitmproxy`
re-signs with a root it generates on first boot — but it could not plant the
other half, and so the whole claim was only ever asserted against fixtures.

The reason is the base image. `node:22.18.0-bookworm-slim` has **no OS trust
store at all**: none of the six paths in `LINUX_PATHS`
(`src/net/os-truststore.ts:124-131`) exist, `/etc/ssl/certs` is empty, and there
is no `ca-certificates` package, no `update-ca-certificates` and no `openssl`.
The OS read therefore returns `reader-missing`/`ENOENT`, `coverage.level` is
`none`, and `evaluate.ts:987` returns early and suppresses the entire runtime
cross-check. Not "the finding does not fire" — the code path is never entered.
There is nothing for a corporate root to be planted *in*.

The bytes that must be planted are mitmproxy's generated CA, and they do not
exist until mitmproxy has booted. They arrive in the `mitm-ca` volume, which is
already mounted read-only into the suite's container at `/pki/mitm` and already
named by `PORTCALL_HARNESS_MITM_CA` in `docker-compose.yml`. Container start is
therefore the earliest moment those bytes exist on any filesystem the suite can
see.

Measured inside the real image, on a Linux docker host, before deciding:

- `apt-get install -y --no-install-recommends ca-certificates` costs **~5 s and
  +8 MB** (230 → 238 MB), pulling `libssl3`, `openssl` and `ca-certificates`.
- After it, the Debian bundle holds **150 roots** and Node 22.18.0's
  `tls.rootCertificates` holds **150**, and the os-not-in-node difference is
  **0** — a clean baseline with no pre-existing noise to explain away. After
  planting one self-signed root the difference is **1**, exactly the planted
  root.
- **`update-ca-certificates` only ingests `/usr/local/share/ca-certificates/*.crt`.**
  mitmproxy's file is `mitmproxy-ca-cert.pem`, so the install must rename to
  `.crt`. A `.pem` is silently ignored.
- **`update-ca-certificates` exits 0 even when it ignores a file**, so `set -e`
  cannot catch that silent failure.
- `openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt <ca.pem>` exits 2
  with `error 18` before the install and 0 with `OK` after — an independent
  check that reads the bundle the distro itself assembled.

## Decision

Two halves, taken together because the second is what bounds the first.

**(a) The image gains `ca-certificates`, and a container `ENTRYPOINT` installs
the run-mounted mitmproxy root into the container's own OS trust store.**
`test/harness/portcall-entrypoint.sh` runs as PID 1, copies
`$PORTCALL_HARNESS_MITM_CA` to
`/usr/local/share/ca-certificates/portcall-harness-mitm.crt`, runs
`update-ca-certificates`, verifies the result with `openssl verify` against
`/etc/ssl/certs/ca-certificates.crt`, and `exec "$@"`. The apt layer sits above
the dependency copy in `portcall.Dockerfile` so an edit to `src/` does not
re-pay the 5 s.

Three properties are load-bearing:

- **The `.crt` rename**, because the measurement says a `.pem` is dropped in
  silence.
- **The `openssl verify` line**, because `update-ca-certificates`' exit code
  cannot report a skipped file. The check proves the planted *condition* — this
  root is now an anchor in the store the OS assembled — rather than the step.
- **The `PORTCALL_HARNESS` gate**, because `portcall.Dockerfile` promises that
  `docker run` on the image alone "does the same thing" as compose. Gated, it
  does: the entrypoint is a no-op, the `CMD` is reached, and the run fails with
  `requireHarness()`'s own message naming the three-command fix, rather than
  dying in a shell script with a worse one.

This rides seams that already exist — the volume, the env var, the `CMD` — and
adds exactly one hook. `PORTCALL_HARNESS_MITM_CA` gains its first code consumer
here; until now it existed only in YAML and `test/harness/README.md`.

**(b) `harnessProfile()` stays at `runtimes: ['node']`**
(`test/integration/harness.ts:79`). Widening to `go`/`python`/`java` proves
nothing new and costs noise. The promotion path is per-`TrustSet` and
runtime-independent: the only thing that differs between runtimes at
`evaluate.ts:770` is which id `RUNTIME_IDS[set.runtime].missingRoot` yields. What
widening *would* add is `store-not-found` findings for three runtimes that are
not installed in this image, changing the blast radius of the four existing
describes for no new evidence.

## Alternatives considered

- **`COPY` the CA and run `update-ca-certificates` at build time.** Cannot work
  at all: mitmproxy generates the root at *run* time into a volume, so at build
  time the bytes do not exist. Nothing in a Dockerfile can see them.
- **Put the install in compose as `command: ['sh','-c','install … && npm run
  test:integration']`.** Breaks `docker run` on the image alone, which
  `portcall.Dockerfile` explicitly preserves, and buries a machine-state
  mutation in YAML where nobody reviewing trust-store behaviour would look for
  it.
- **Commit a CA certificate and key and point mitmproxy at them.** A CA private
  key in a public repository, against SPEC.md §4 and the standards, and not
  worth arguing further. It also *weakens* the claim: the installed root would
  no longer provably be the root signing the traffic the TLS probe captured,
  which is precisely the correlation under test.
- **Install the root from the suite's `beforeAll`.** `requireHarness()`
  (`test/integration/harness.ts:115-126`) gates on an environment variable a
  developer can set on a laptop, so that code would sit one `PORTCALL_HARNESS=1`
  away from mutating a real machine's trust store. An `ENTRYPOINT` baked into
  the harness image cannot run anywhere but inside that image.
- **Skip apt entirely and write a one-certificate bundle with `cat`** to
  `/etc/ssl/certs/ca-certificates.crt` — roughly two lines, 0 MB, 0 s. This is
  the closest alternative and the argument against it has to be stated
  honestly, because the tempting version of it is false. It is **not** true that
  the cheap variant proves nothing: `src/net/os-truststore.ts:124` reads that
  path directly with no subprocess, so both variants exercise byte-identical
  `src/` code, and both yield `locallyAdded = [the mitm root]`. The real
  warrant is narrower and has two parts. **Fixture fidelity:** apt plants what a
  real corporate laptop has — 150 public roots plus one corporate root — where
  the `cat` variant plants a one-root store no machine on earth has, and a
  harness that plants an impossible machine is weaker evidence than one that
  plants a plausible one. **An independent self-check:** `openssl verify`
  against a store the distro assembled from its own inputs can catch a silent
  skip; the `cat` variant can offer no such check, because anything it verified
  would only be re-reading the file it had just written. The price of both is
  8 MB and 5 s, which is noise against a build that already runs `npm ci`.
- **Widen `harnessProfile()` to more runtimes** — see decision (b).

## Consequences

- **The M4 cross-check is reachable live for the first time.** With the store
  planted, the OS read yields real coverage, `correlate()` runs, and the
  `blocker` promotion is provable against a real handshake rather than a
  recorded chain. The test that asserts it is a separate work package; this one
  only makes it possible.
- **SPEC.md §4 is not strained, and the reason is structural.** The only
  trust-store write happens in a script that exists solely inside the harness
  image, reading a `:ro` mount, in a container the suite `--rm`s after the run.
  No host store, CI runner store, or developer store is reachable from any code
  path this adds — not because the script checks, but because there is no
  invocation of it from outside the image. No `src/` code changed.
- **That warrant is invocation locality, and it is the kind that can lapse.**
  The script's only functional guard is `PORTCALL_HARNESS=1`, which any
  developer can export; what actually keeps it off a host is that nothing
  outside the image invokes the `.sh` at all. The moment something does - a
  convenience npm script, a CI step calling it directly, someone sourcing it to
  debug a planting failure - the property is gone, and the gate is social rather
  than structural. The fix at that point is one line at the top of the script,
  `[ -f /.dockerenv ] || exit 1`, which asks the container instead of the
  caller. It is deliberately not there today: it would be an untested branch
  guarding an invocation that does not exist, and it would make the harness
  depend on a Docker implementation detail for a property the file layout
  already gives it for free. Add it with the first such caller, and not before.
- **The harness image is 8 MB larger and its cold build ~5 s longer.** Stated in
  `test/harness/README.md`'s limitations rather than hidden. The layer sits
  above `COPY package.json`, so the cost is paid on a base-image or Dockerfile
  change and not on ordinary `src/` edits.
- **`docker-compose.yml`'s mitmproxy comment had to change.** It justified
  `ssl_insecure=true` with "the harness has no store to install one into", which
  this decision makes false. The flag is still needed, for a different reason:
  the root mitmproxy would need is the *origin's*, and mitmproxy's store is a
  different container's from the one now planted.
- **The harness now plants a condition with no service of its own**, which the
  compose header's "one service each" framing did not allow for. That header was
  already miscounting (four claimed, five listed) and is rewritten to say six
  conditions, five services, and where the sixth comes from.
- **A `.crt` file appears in the container at a path no test names.** If a later
  change moves the install path or the filename, `update-ca-certificates` will
  keep exiting 0 while planting nothing; the `openssl verify` line is the only
  thing standing between that and a green run that proves nothing. It is not
  decoration and should not be removed as noise.
