# ADR-0047: The demo recording is a tape rendered in CI, and the committed GIF is a snapshot

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

ADR-0046 gave the project a demo worth recording: `npm run demo` brings the
hostile network up, runs a real `portcall check` inside it, and requires the
check to exit 2. What was still missing is the recording itself — SPEC.md §11
asks for "a short screen capture for the site", and a screen capture is the one
artefact in this repo that nobody can review, because it arrives as pixels with
no history and no provenance.

Three things about that make it a decision rather than a chore.

**A recording rots differently from code.** Everything else here is checked on
every push: the probes have fixtures, the harness has an integration suite, the
profiles have a freshness gate (ADR-0044). A GIF checked into the repo is
checked by nothing. It keeps showing last quarter's report long after the
report's shape has changed, and it does it while sitting at the top of the
README, which is the most-read and least-verified position in the project.
ADR-0045 already had to answer the same shape of problem for the "self-contained
HTML" comment: a claim that reads as current while being a static assertion is
the overstating problem, and CLAUDE.md is explicit that understating is fine and
overstating is not.

**`vhs` exits 0 whether the command it recorded worked or not.** This is the
detail that decides the CI job's shape, and it was missed in the first pass at
this plan. VHS's job is to drive a pseudo-terminal and encode the frames; the
exit status of whatever ran inside that terminal is not its business, and it
does not propagate it. So a job whose only step is "render the tape" is green
when the demo is broken, and its artifact is a polished recording of a stack
trace or of a report full of `ok` — precisely the thing ADR-0046 built an
exit-code assertion to prevent, reintroduced one layer up. The codebase map
already records this shape under `build:binaries`: a step that looks like
verification, is not, and stays green until the moment it matters.

**The demo needs Docker, and SPEC.md §11 says it does not.** The section says
"on a machine with nothing installed". That was never true of this demo and
could not be: the demo *is* five containers. It is a small inaccuracy in an
internal document, but it is the sentence a README paragraph would be written
from, and a README that promises a zero-install demo of a thing that needs
Docker is exactly the overstatement M5 is supposed to avoid.

## Decision

**The recording is a VHS tape (`demo/portcall-demo.tape`) rendered by a
dedicated `demo` job in CI. The job runs `node scripts/demo.mjs` as its own step
*before* the render, so the assertion is a real step and the tape only produces
the artifact. `demo/portcall-demo.gif` is a hand-refreshed snapshot of a green
render, described as such wherever it appears. SPEC.md §11 is amended to say all
of this and to drop "a machine with nothing installed".**

Concretely:

1. `demo/portcall-demo.tape` types `npm run demo`, waits on the shell prompt
   with a timeout matched to the job's own, and holds the last frame — the tail
   of the report, the teardown, and the exit-2 verdict. It comments why each
   number is what it is, because framerate and playback speed are the two
   settings that decide whether the GIF is a few megabytes or a few tens of
   them.
2. The `demo` job is separate from `harness`, ubuntu-only, `timeout-minutes:
   20`. Separate for the reason `truststore-proof` is separate: a red job that
   names one claim is worth more than a red job that could mean four things.
3. **`node scripts/demo.mjs` runs first, as its own step.** A broken demo
   reddens CI on ADR-0046's exit-2 assertion, not on a subjective look at a GIF
   nobody opens.
4. `charmbracelet/vhs-action` is pinned to a commit SHA with the tag in a
   trailing comment, the same form as `oven-sh/setup-bun` in the `verify` and
   `binaries` jobs, and for the same reason: it is third-party code in this
   project's CI and a tag is a mutable pointer.
5. The GIF is uploaded with `actions/upload-artifact@v7` and
   `if-no-files-found: error`. **CI does not diff it against the committed
   copy.**
6. The `harness` job gains the `docker compose build portcall` step it was
   missing, so that all four commands in `test/harness/README.md`,
   `scripts/demo.mjs`, and CI are the same four commands in the same order.

## Alternatives considered

**Render the tape and let a green job stand as the assertion.** Rejected, and
this is the one that mattered. It is what the first draft of this plan said, and
it is wrong for the reason in the context above: `vhs` reports on the recording,
not on the recorded. The cost of getting it wrong is not a broken build — it is
a *green* build whose published artifact is a recording of a failure, which is
worse than no recording, because it is evidence pointing the wrong way. The fix
is one extra step and a few minutes of runner time.

**Diff the rendered GIF against the committed one and fail on a mismatch.**
Rejected. It is the tempting answer to staleness and it does not survive
contact: the recording's frame count is a function of how long Docker took to
pull, build and health-check five services on that particular runner. Two
identical tapes produce different files. A gate that fails for reasons unrelated
to the change under review gets ignored within a week, and an ignored gate is
worse than an absent one because it still costs the runner minutes and still
occupies the space where a real check could have gone.

**Regenerate the committed GIF from CI on every push and commit it back.**
Rejected for boring reasons. It needs a write token on a public repo, it puts a
binary blob in the history of every push, and it makes the recording a thing CI
owns rather than a thing a human chose to publish. The blob is the decisive one:
a few megabytes per push, permanently, to keep current a file whose whole
purpose is to be looked at twice.

**asciinema plus `svg-term-cli`.** Rejected. It produces a smaller, sharper,
selectable-text SVG, which is genuinely better output than a GIF. But it is two
tools instead of one, the recording step is interactive by default rather than
declarative, and neither is in this repo already. The deciding factor is that a
VHS tape is a *reviewable text file*: the terminal size, the typing speed, the
waits and the reasons for them all sit in the diff, where the parts of this
decision that could go wrong are visible. An asciinema cast is a JSON transcript
of one person's session — the same unreviewable artefact as a hand-made capture,
with better compression.

**A hand-made screen capture from a laptop.** Rejected. It is faster once and
unmaintainable afterwards: nobody can tell what version it shows, it embeds
whatever the recorder's terminal, font and hostname happened to be, and
re-recording it means finding the one person with the setup. It also risks
putting a real machine's environment on the project's front page, which for a
tool whose whole subject is what a corporate network is doing to your traffic is
a bad look on the merits.

**Skip the committed GIF entirely and link to the CI artifact.** Rejected.
Artifacts expire, need a GitHub login to download, and cannot be embedded in a
README. The demo exists to be seen by someone reading the repo cold; a link that
asks them to authenticate and unzip is not a demo.

**Drop §11's "nothing installed" line silently.** Rejected on this repo's own
terms. SPEC.md is a public document and its history is public; an inaccuracy
that gets quietly edited away reads worse than one that is corrected in place
with a reason. The amendment says what was wrong and what is true instead.

## Consequences

- The demo is now covered on every push, and covered by an assertion rather than
  by a render: `demo` goes red when `portcall check` stops finding the planted
  conditions, independently of whether anyone looks at the GIF.
- CI runs the demo network twice per push — once in `harness`, once in `demo` —
  plus a third compose cycle inside the tape's own `npm run demo`. That is the
  price of the assertion-before-render split, paid in runner minutes on the
  cheapest OS. The 20-minute timeout is set for it; if the job starts brushing
  that ceiling, the honest fix is to make the tape record a shorter run, not to
  drop the assertion step.
- **`demo/portcall-demo.gif` is not produced by the change that introduced this
  ADR.** `vhs` is not installed on the authoring machine, and the definition
  above is "a snapshot of a green CI render" — no green render existed yet, so
  committing a locally improvised GIF would have been the same overstatement in
  a different costume. The file is populated by hand from the first green `demo`
  job's artifact. Nothing in `npm run verify` or in CI depends on its presence.
- The tape's framerate and playback speed are unmeasured. They are commented as
  such, and the first real artifact is what settles them. A GIF too large for a
  README is a tuning problem with two obvious knobs, not a design failure.
- `demo:record` (ADR-0046) stops being inert: `npm run demo:record` now renders
  something. `vhs` is still not a repo dependency and is still not installed by
  anything here.
- The `harness` job's added build step changes no behaviour today. It was
  correct by accident — a fresh runner has no image, so `up --wait` built one —
  and the accident is a property of the runner rather than of the workflow.
