# ADR-0045: The self-contained HTML claim is a static enumeration, not a rendered load

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

`src/report/html.ts` renders the one artefact of this tool that leaves the
customer's network on purpose. A forward-deployed engineer runs `portcall`
inside a network he does not own, writes the HTML report to a file, and emails
it out for a decision. The person who opens it is a security reviewer who is,
correctly, suspicious of a binary someone brought onto their laptop. If that
page fetches a stylesheet, a font or a favicon on open, it has made a network
call the operator never authorised, and it does so in front of the one reader
whose whole job is noticing. The self-contained property is therefore not a
performance nicety; it is the load-bearing claim of the artefact.

M5 makes the repo's claims public. The file's header comment ended with:

> A CI test asserts the output loads no subresources.

That sentence is false in a specific and unflattering way. `test/guardrails/
html-self-contained.test.ts` never loads anything. It calls `renderHtml`, gets
a string back, and pattern-matches that string. Before this decision it looked
for five substrings — `src=`, `<script`, `<link`, `url(`, `@import` — plus one
genuinely strong rule: every `https?://` occurrence in the document must also
appear inside an `<a href="…">`. A reader who takes the comment at face value
believes a browser opened the page and no request went out. Nothing of the kind
happened.

CLAUDE.md's rule for this repo is "understating is fine; overstating is not",
and `src/report/html.ts` is the first file a suspicious reviewer opens, because
it is the file that produced the document in front of him. A comment that
overstates its own test there costs more credibility than the check buys.

The honest question is what a string scan can be worth. Two properties of this
particular renderer decide it:

- **The template is fixed and hand-written.** `src/report/html.ts` is 226
  lines of string concatenation with no interpolation of caller-supplied tag names, no
  template engine, and no partials. Its entire tag vocabulary — `html`, `head`,
  `meta`, `title`, `style`, `body`, `main`, `h1`–`h3`, `p`, `div`, `table`,
  `tr`, `th`, `td`, `article`, `code`, `span`, `footer`, `a` — is readable in
  one sitting. An enumeration is a complete check over a vocabulary a human can
  hold in his head, and this one is.
- **Every value is escaped, and the only URL is an anchor.** `escapeHtml`
  covers all five HTML special characters; `safeHref` admits only `http:` and
  `https:` and returns `undefined` for everything else, so `docs` is the sole
  field that becomes a link. Evidence, titles and remediations are inert text.

That is why the enumeration is not theatre — but it is also exactly why the
claim must be stated as an enumeration. Its soundness is a property of the
template, not of the test.

## Decision

**The self-contained claim is a static tripwire over an enumerated list of
fetch-triggering constructs, and both the source comment and the test say so.**

Three parts:

1. The header comment in `src/report/html.ts` is reworded to name the
   enumeration, name the URL rule, and state plainly that nothing opens the
   file — "a static tripwire on a fixed template, not a load check" — and that
   the claim holds only as far as the enumeration does and only while the
   renderer stays hand-written string concatenation.
2. The enumeration is widened by five constructs that are plausible in this
   template *and* invisible to the URL rule: `<iframe`, `<object`, `<embed`,
   `srcset=`, and an `http-equiv="refresh"` meta. The first three fetch through
   attributes of their own; `srcset=` carries a URL list that the existing
   `src=` substring does not match; a meta refresh navigates on open and, with a
   relative target, carries no absolute URL for the anchor rule to catch.
   Constructs that *would* be caught by the URL rule whatever tag carries them —
   `poster=`, `background=`, `<use`, `style="…url("` — are deliberately not
   added, because a longer list that adds no coverage reads as diligence and
   is not.
3. The scan runs over a second, wider document: the golden report
   (`goldenReport()` in `test/helpers/report-fixture.ts`, whose rendered JSON is
   pinned byte for byte by `test/fixtures/report/golden-report.json`). It
   carries one finding per `Severity` and one piece of evidence per
   `EvidenceKind`, so every branch of `renderFinding` — badge, evidence table,
   fix block, docs anchor — is on the page the scan reads.

## Alternatives considered

**Render the page in a headless browser and assert zero requests.** This is the
check the old comment described, and it is the only thing that would make the
sentence true. Rejected for a boring reason: a browser automation dependency
(Playwright or Puppeteer) downloads a Chromium build per runner — hundreds of
megabytes, *unverified:* not measured here, because the order of magnitude
settles it and is not close. Nine of this repo's ten CI runs install the
dependency tree (`verify` ×3, `truststore-proof` ×3, `node-compat` ×2,
`binaries`; measured against `.github/workflows/ci.yml`), so the download lands
in each of them, on three operating systems. It would buy a real load check
over 226 lines of string concatenation whose entire output a reviewer can
read.

The weight is not the whole objection. Every dependency in this repo is a line
item in a customer's security review — that is why `cli/args.ts` is hand-rolled
argv parsing, why PAC evaluation uses `node:vm` (ADR-0010), and why
`@peculiar/x509` had to be argued for and then scoped (ADR-0021). Adding the
largest dependency in the tree, transitively pulling a browser, to a tool whose
selling point is that it reads nothing and installs nothing would be a poor
trade even if it were free.

**Commit a golden `report.html` and diff it byte for byte.** Rejected. M5's own
deliverable is the HTML report; copy and CSS are expected to change during it. A
~200-line committed blob taxes every one of those edits, and the response to a
red diff on an intended change is to hand-edit the golden until it matches —
which is precisely the failure mode goldens exist to prevent. What is pinned
instead is the *input*: one golden report, its rendered JSON committed, and its
HTML re-derived by calling `renderHtml` at test time. A copy edit moves no
fixture; a schema change moves exactly one.

**An `UPDATE_GOLDEN=1` regeneration flag.** Rejected. A golden that rewrites
itself on a red run stops catching anything the moment someone is in a hurry.
The regeneration command lives in the test's doc block instead, as one line a
human runs deliberately before reading the diff.

**Say nothing and leave the comment.** Rejected outright. The overstatement is
in the file a security reviewer opens first, and M5 is the milestone that makes
it public.

## Consequences

- The claim in `src/report/html.ts` is now checkable against the test that
  backs it: the comment lists the constructs, the test asserts them, and a
  reader can compare the two in under a minute.
- **The stated limitation is real and is the follow-up trigger.** The
  enumeration is sound because the template is fixed and hand-written. It would
  not survive templating the renderer, accepting caller-supplied markup, or
  adding a tag whose fetch behaviour is not on the list. Anyone doing one of
  those things has to replace this tripwire with a real load check, and the
  comment and the test both say so at the point they would be edited.
- A construct absent from the list passes unnoticed. That is inherent to an
  enumeration and is the price of not shipping a browser. The URL rule limits
  the blast radius: whatever tag carries an *external* target, an absolute URL
  outside an `<a href>` fails the test.
- The golden JSON fixture is compared newline-agnostically (CRLF folded to LF,
  trailing whitespace trimmed). The repo has no `.gitattributes`, and
  `core.autocrlf=true` is set on the development machine this was written on
  (measured) and is *unverified:* believed to be the default on the
  `windows-latest` runner too. Under it a checkout rewrites the committed
  fixture, and a byte-exact comparison would redden `verify` on line endings
  alone. No value in the
  report contains a newline, so the folding cannot mask a real difference. This
  ADR does not introduce a repo-wide `.gitattributes` convention; if one is
  wanted later it is its own decision.
- `REPORT_SCHEMA_VERSION` is public API and now has a whole-document fixture
  behind it, not only the key-order assertions in `test/report-json.test.ts`.
  A schema change that a reviewer should see becomes a fixture diff.
