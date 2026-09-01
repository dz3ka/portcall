# ADR-0048: Release checksums are signed with Sigstore keyless; the binaries stay unsigned

- **Status:** Accepted
- **Date:** 2026-09-01
- **Deciders:** Bogdan Dzekic

## Context

M5 ships the thing SPEC.md §5 promised: five self-contained executables, built by
`scripts/build-binaries.mjs` and published on a GitHub release. One of M5's exit
criteria is *signed checksums*, and the reason it is an exit criterion at all is
the deployment story portcall is built around. The tool is downloaded by someone
on a locked-down corporate laptop, in the environment portcall exists to
diagnose — an environment where a TLS-intercepting proxy is not a hypothetical
but the *expected* condition. Handing that person an unauthenticated 60 MB
executable over a link, from a tool whose entire pitch is "your traffic is being
re-signed by something", would be self-refuting.

Three constraints shaped the answer.

**No key custody.** This is a one-maintainer public repository. Any signing
scheme with a private key has to answer where the key lives, who can use it,
what happens when it leaks, and what a revocation looks like — and the honest
answer for a solo project is "in a GitHub secret, forever, with no rotation
story". A leaked signing key is strictly worse than no signature, because it
lets an attacker produce artifacts that verify.

**The verification has to be something a stranger will actually run.** A
signature nobody checks is decoration. The realistic budget is one or two
commands pasted from the README, on a machine that has neither the project's
tooling nor an account anywhere.

**The README's honesty claim must survive.** CLAUDE.md and SPEC.md §3 commit the
README to saying plainly that *binaries are unsigned until v2*. There is no
Authenticode certificate and no Apple notarisation: Windows SmartScreen and
macOS Gatekeeper will still complain. Whatever is signed here must not make that
sentence false, or make a reader think it is false.

There is also a non-constraint worth naming, because it looks like one. SPEC.md
§4 forbids telemetry. Sigstore's Rekor transparency log is public and receives
an entry for every signature. That entry is release infrastructure, produced by
a GitHub runner at tag time; `portcall` the binary never contacts Rekor, never
contacts Fulcio, and behaves identically whether or not any of this exists.

## Decision

**The `SHA256SUMS` manifest is signed with Sigstore keyless — cosign plus the
GitHub Actions OIDC token — and nothing else is signed.**

`.github/workflows/release.yml` runs on a pushed `v*` tag. Its single `release`
job overrides the workflow's `contents: read` with `contents: write` (to publish
the release) and `id-token: write` (to mint the OIDC token). It reads no
repository secret. It builds, re-checks the manifest against the files on disk,
signs, verifies its own signature, and publishes seven assets: the five
executables, `SHA256SUMS`, and `SHA256SUMS.cosign.bundle`.

The signed input is `build/binaries/SHA256SUMS` and not the binaries. That is not
a shortcut — the manifest already commits to all five executables by SHA-256, so
one signature covers the whole release transitively, and `formatChecksums`
(`scripts/build-binaries.mjs:63`) already emits it sorted and in `sha256sum -c`
format, so it is byte-identical across runs. Signing the binaries individually
would produce five bundles and ask a stranger for five `verify-blob` calls to
learn the same fact.

What a stranger runs, in full:

```
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/dz3ka/portcall/\.github/workflows/release\.yml@refs/tags/v'
sha256sum -c SHA256SUMS --ignore-missing     # macOS: shasum -a 256 -c
```

Read the first command as the claim it makes: *this manifest was signed by a
GitHub Actions run, of the file `release.yml`, in the repository `dz3ka/portcall`,
triggered by a `v` tag.* It pins the issuer, the repository, the workflow **file
name**, and the ref shape. The second command then extends that claim to the
bytes on disk. Nothing is trusted because it came from a particular URL.

Two consequences of that regexp are properties of the workflow file, not of the
README: **the file must be named `release.yml`** and **it must trigger only on
`refs/tags/v*`**, because Fulcio writes the workflow ref into the certificate's
SAN as `https://github.com/OWNER/REPO/.github/workflows/FILE@REF`. Renaming the
file or widening the trigger silently breaks a published command. The workflow
therefore runs that exact `verify-blob` invocation against its own output,
before uploading anything, so a rename fails the release rather than shipping
instructions that do not work.

**The binaries stay unsigned until v2.** Code signing is a different problem with
different economics: an Authenticode certificate and an Apple Developer
membership, both annual, both attached to a legal identity, and neither of which
Sigstore replaces. Sigstore answers "did this come from that workflow"; it does
not answer "will SmartScreen stop shouting". The README says so.

## Alternatives considered

- **minisign, or a GPG detached signature.** The obvious answer, and rejected on
  the one constraint that matters most: key custody. The private key would live
  in a GitHub Actions secret with no rotation story and no revocation story, and
  its compromise would be silent — an attacker with the key produces artifacts
  that verify perfectly, and no log anywhere records that a second signer
  appeared. It is also worse for the reader: verifying a GPG signature means
  first obtaining the right public key through some out-of-band channel and
  deciding to trust it, which is the entire problem restated one level up.
  Sigstore's answer is that there is no long-lived key to obtain, and the
  identity being verified is one GitHub already publishes.
- **`actions/attest-build-provenance`.** Genuinely close, and it produces
  strictly richer information — SLSA provenance about the build, not just a
  signature over a file. It lost on two counts. Verification is
  `gh attestation verify`, which means a stranger needs the GitHub CLI installed
  and, in practice, authenticated, where `cosign verify-blob` needs one static
  binary and no account. And it pins less legibly: the trust decision is
  expressed as flags to `gh` against a GitHub-hosted attestation store, rather
  than as a regexp the reader can look at and see, character by character, which
  repository and which workflow file are being asserted. For a repo whose stated
  purpose is that its reasoning be legible to someone reading it cold, the
  more transparent artifact wins over the more complete one. This is not a
  permanent judgement; it is the right revisit at v2, alongside code signing.
- **Signing each of the five executables instead of the manifest.** Five
  bundles, five `verify-blob` commands, five things to get wrong, and no
  additional assurance — `SHA256SUMS` already binds all five by digest, so the
  manifest signature covers them transitively. It would also make the release
  page harder to read.
- **Self-hosted or keyed cosign (`cosign sign-blob --key`).** Keeps cosign's
  tooling and reintroduces exactly the custody problem the decision refuses.
- **Publishing checksums with no signature at all.** The status quo, and it
  fails against the actual threat model. An attacker who can replace a release
  asset can replace `SHA256SUMS` alongside it; an unsigned manifest only detects
  accidental corruption, which is not what the download path of this particular
  tool is exposed to.

## Consequences

- **No key material exists anywhere, at rest or in a secret.** The signing
  certificate Fulcio issues is valid for roughly ten minutes and is bound to the
  OIDC token the runner minted for that job. There is no key to leak, rotate,
  lose, or hand over, and nothing in this repository's settings has to be
  guarded as a signing credential.
- **The elevated permissions live in a file that only runs on a tag.** Workflow
  level is `contents: read`; only the `release` job widens it. Nothing a pull
  request — including one from a fork — can trigger will ever hold
  `id-token: write` or `contents: write` in this repository.
- **The Rekor entry is public, and that is fine.** It contains the manifest's
  digest, the certificate, and the workflow identity. It contains nothing about
  any customer, any network, or any run of the tool. SPEC.md §4's no-telemetry
  non-negotiable is about `portcall`, and `portcall` still makes no network call
  outside the active profile — this is release infrastructure, not the tool.
- **The README gains a verification section and keeps its unsigned-binaries
  sentence.** Both are true at once and the README has to say so without
  hedging: the *checksum manifest* is signed, the *executables* are not, and
  Windows and macOS will still warn on first run.
- **The workflow's filename and trigger are now public API.** `release.yml` and
  `refs/tags/v*` appear inside a certificate that a published command matches
  against. Renaming or retriggering is a breaking change for every reader who
  copied the command, and the in-workflow `verify-blob` step exists to make that
  break loud at release time rather than silent.
- **This path first executes on the tag that matters.** Same shape of risk as
  `build:binaries` before it: nothing in `ci.yml` can exercise a tag-triggered,
  OIDC-signing job, so the first real run is the first real release. The
  mitigation is a rehearsal on a throwaway tag — cut `v0.1.0-rc.1`, download the
  published assets onto a clean machine, run the two README commands verbatim,
  then flip one byte of `SHA256SUMS` and confirm `verify-blob` fails. That
  rehearsal is owed before any `v0.1.0` tag is pushed; until it has been done,
  treat this workflow as unexercised.
- **cosign's major version is pinned through the action.**
  `sigstore/cosign-installer` is pinned by commit (`# v4.1.2`), which installs
  cosign 3.0.6. cosign 3 removed `--b64`, `--output-signature`,
  `--output-certificate` and `--new-bundle-format` from `sign-blob`; the
  protobuf bundle written by `--bundle` is now the only output shape, and it is
  what `verify-blob --bundle` consumes. Moving the pin is therefore a decision
  about the verification command too, not a routine dependency bump.
