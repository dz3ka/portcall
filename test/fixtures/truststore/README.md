# `truststore` fixtures

## What is here

- `record-stores.ts` — the recorder. Run it manually, or from a CI job on the platform being
  recorded. It spawns the platform's row of the pinned command table (`src/net/os-truststore.ts`,
  ADR-0033) and writes the child's raw stdout, plus a JSON sidecar describing how the capture was
  produced.

## What is deliberately *not* here

**There is no macOS fixture, and one must not be written by hand.**

`security find-certificate -a -p <keychain>` has never been executed by anyone on this project.
The Windows reader was measured on real hardware (41 roots, ~0.9 s, one unwrapped base64 DER per
line, exit 0, empty stderr) and the command table records that. The macOS command's output shape
is taken from Apple's documentation — it is a guess, and `src/net/os-truststore.ts`'s `pem-stream`
branch is written against that guess.

A hand-authored fixture would hide exactly that. It would be a file asserting the shape the parser
already assumes, passing for the same reason the parser passes, and proving nothing. So the macOS
parser path is covered instead by:

1. synthetic PEM minted in-process by `test/helpers/synthetic-chain.ts` (`test/net-os-truststore.test.ts`),
   which tests the *parser* against input this repo generated and never claims to be a recording; and
2. this recorder, which captures the real thing.

## Retiring the assumption

The throwaway CI branch must run, on a `macos-latest` runner:

```
node test/fixtures/truststore/record-stores.ts
```

and upload `test/fixtures/truststore/darwin/` as a build artifact. Two rows are recorded there:
`macos-system-roots.txt` (Apple's shipped roots) and `macos-admin-anchors.txt` (MDM/admin
installs — often empty on a clean runner, which is itself a result worth recording).

What to check in the sidecar JSON:

- `exit` is `0` and `stderrBytes` is `0`;
- `stdoutBytes` is non-zero for `macos-system-roots`;
- the text is a run of `-----BEGIN CERTIFICATE-----` blocks with nothing between them that the
  `pem-stream` parser would have to understand. If `security` prefixes each block with a
  `Certificate:` header or an attribute dump, the parser already skips it — `pemBlocks` matches
  blocks, not whole files — but the recording is what turns that from a hope into a fact.

If the shape differs from the guess, the fix is a new `format` value in the pinned table, not a
redesign: the parse is one field of one row.

The same CI run is also where WP4's `cacerts` container-format probe is measured, so one paid run
retires both assumptions.

## Recording etiquette

Record on a clean CI runner, never on a customer machine. The captures are public root CA
certificates and contain no key material, but a corporate machine's `Root` store also names that
company's internal CA, and that does not belong in a public repository.
