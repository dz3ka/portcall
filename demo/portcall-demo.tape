# The recording behind SPEC.md §11: one command, the hostile network, and
# portcall naming what is wrong with it.
#
# Rendered by CI's `demo` job on every push, and by `npm run demo:record` on a
# machine that has vhs (https://github.com/charmbracelet/vhs). It is not
# rendered by `npm run verify`: vhs is not a repo dependency and nothing here is
# a test.
#
# `demo/portcall-demo.gif` is a hand-refreshed snapshot of one green `demo`
# job's artifact, not a file CI keeps current. CI deliberately does not diff the
# two - frame timing is not reproducible enough to gate a build on - so the
# committed GIF can lag this tape, and is described that way wherever it is
# embedded (ADR-0047).
#
# Nothing in this file asserts anything, and it must not be read as if it did:
# vhs exits 0 whether the recorded command succeeded or failed, so a tape alone
# would happily publish a GIF of a stack trace under a green tick. The `demo`
# job runs `node scripts/demo.mjs` as its own step *before* this tape for
# exactly that reason (ADR-0047). The only failure vhs can still report here is
# the `Wait` below timing out.

Output demo/portcall-demo.gif

# What the recording needs from the host. `Require` is checked before a single
# frame is captured, so a runner without Docker produces a one-line error
# instead of a four-minute recording of `npm run demo` explaining that Docker is
# missing. `scripts/demo.mjs` needs nothing else - it shells out to compose, and
# the product itself is built and run inside the container.
Require docker
Require npm

# Roughly 130 columns by 50 rows at this font size. The text report rules at 72
# columns (`src/report/text.ts`) and `docker compose` prefixes every line with a
# service name, so 130 columns is what keeps compose's output off a second line.
# The height is chosen for the last frame rather than the middle ones: it is
# what holds the tail of the report, the teardown and the verdict on one screen,
# and that is the frame a reader actually stops on.
Set FontSize 15
Set Width 1200
Set Height 1000
Set Padding 20

# A blinking cursor changes pixels on frames where nothing else does. For a
# recording that is mostly a static screen waiting on Docker, that is most of
# the frames, and every one of them costs GIF bytes for no information.
Set CursorBlink false

# The two settings that decide whether this GIF is a few MB or a few tens of
# them, and the ones to argue with first if it lands too large. `npm run demo`
# is two compose cycles and an image build - minutes of wall clock - and vhs
# captures `Framerate` frames for every second of it. 10fps is well below what a
# UI recording would want and entirely adequate for scrolling log text;
# `PlaybackSpeed 4` then plays those frames back four times faster, so a run of
# a few minutes lands near a minute of GIF. Neither number has been measured
# against a real render yet - the first green `demo` job's artifact is what
# settles them.
Set Framerate 10
Set PlaybackSpeed 4

Type "npm run demo"
Sleep 500ms
Enter

# The whole demo, in one wait. With no pattern, `Wait` matches vhs's default
# prompt regex on the last line, so this returns when the shell prompt does -
# that is, when `scripts/demo.mjs` has brought five healthchecked services up,
# rebuilt the image against this checkout, run `portcall check` through the
# intercepting proxy, and torn the network down again.
#
# 15m, comfortably inside the `demo` job's 35: the job clock also covers the
# assertion run that precedes this render, so the two budgets are not the same
# number and vhs must be the one that gives up first.
# A shorter one would mean vhs kills the recording first on a hung compose, and
# the only evidence left would be a GIF of a half-finished run; at parity, the
# job's own timeout fires and CI keeps the logs. Seconds, not `20m`, because
# seconds is the unit every other duration in this file uses.
Wait@900s

# The frame a reader stops on: the end of the report, the teardown, and the
# closing line saying the check exited 2. Exit 2 is `blocker` (ADR-0006) and
# here it is the pass condition rather than a failure - a run of this network
# that found nothing would have demonstrated nothing (ADR-0046).
Sleep 5s
