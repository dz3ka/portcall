# ADR-0036: Java keystores are parsed in-process, and portcall never supplies a password

- **Status:** Accepted — retroactive write-up. The decision is M4's design item
  D8, cited from `src/net/types.ts` and SPEC.md §4.2 as of `c3130c9`
  (2026-08-28) and implemented in `0d89a38` ("Add a hand-rolled Java keystore
  reader for the truststore cross-check (WP4)", 2026-08-31). The record itself
  was never written; what follows is the reasoning already carried in D8, in
  that commit, and in `src/net/java-keystore.ts`'s header
- **Date:** 2026-09-01 (decision: 2026-08-28, implemented 2026-08-31)
- **Deciders:** Bogdan Dzekic

## Context

The M4 cross-check has to read a JDK's `cacerts` to say which of this machine's
roots that JDK cannot see. `cacerts` is not a PEM bundle: it is a JKS container
on older JDKs and a PKCS#12 container on JDK 9 and later, and both are binary
formats that have to be walked.

The two obvious ways to walk them are both closed.

`keytool -list -cacerts -storepass changeit` is closed twice over. ADR-0033 says
exactly one file in `src/` may start a process and only from a pinned table of
public-certificate enumerations, and `keytool` is not in that table. SPEC.md §4.2
independently forbids ever supplying a password, *including the documented
default password of a Java keystore* — the wording names this case specifically,
because "it is only `changeit`" is the argument that would otherwise win.

A keystore-parsing dependency is closed by the no-new-dependency constraint on
this probe's runtime surface. It also sits outside what the guardrails can see:
`no-credential-access.test.ts` and `x509-parse-only.test.ts` are textual scans
over `src/`, so a library's password-bearing API is beyond their reach by
construction.

There is a third pressure, subtler. A keystore is the one place in this whole
probe where public trust material and private key material sit in the same file.
Whatever reads it walks past `PrivateKeyEntry` blobs and `pkcs8ShroudedKeyBag`s
on the way to the certificates it wants.

## Decision

**Portcall parses JKS and PKCS#12 itself, in a pure module, with zero
cryptography and no password of any kind.**

- `src/net/java-keystore.ts` is a hand-rolled reader: `readKeystore(bytes)`,
  bytes in, DER out. It has **no `node:` import at all**, so it is
  fixture-testable without a filesystem and the `x509-parse-only` guardrail's
  node-import ban would hold there even if the file were added to its scanned
  directories.
- **Zero cryptography.** It never verifies a JKS integrity MAC, never decrypts a
  PKCS#12 `encryptedData` bag, and never supplies a password — not the
  operator's, not a prompt, not `changeit`.
- **Private key material is skipped by length, never opened.** Only a
  `TrustedCertEntry` (JKS) or a `certBag` holding an `x509Certificate` (PKCS#12)
  is ever returned. The certificate chain that rides along a `PrivateKeyEntry` is
  plain DER and is *still* skipped, so there is exactly one path by which a
  certificate can reach the caller.
- **Format is decided by the first bytes, never by a file name.** `FEEDFEED` is
  JKS; `CECECECE` is JCEKS, a second sealed-key format no default `cacerts` uses,
  reported `unsupported-format` rather than parsed; a DER `SEQUENCE` header is
  PKCS#12; anything else is `unsupported-format`. Indefinite-length BER inside a
  PKCS#12 walk is `unsupported-encoding`, not a best-effort parse.
- **An unreadable store is an outcome, not an exception** (ADR-0008).
  `encrypted` means every bag sat inside `encryptedData` and nothing was
  extracted; `no-certificates` means the walk succeeded and the store held none;
  `partial` means some `SafeContents` were plain and others encrypted, with the
  readable half returned and flagged.
- **Bounded by construction.** Every length is checked against the remaining
  buffer before use, DER nesting is capped at `MAX_DER_DEPTH`, and the
  certificate count at `MAX_KEYSTORE_CERTIFICATES` — once reached, the walk stops
  collecting rather than failing.
- The probe reports `encrypted` and `partial` at `severity: unknown` and tells
  the operator to run `keytool -list -keystore <path>` **themselves** and compare.
  Portcall names in prose a tool it does not run, and says plainly that the
  anchors it could not read may be the ones being looked for.

## Alternatives considered

- **Shell out to `keytool`.** Rejected twice: ADR-0033 permits no such row, and
  SPEC.md §4.2 forbids supplying the password `-storepass` needs — the
  guardrail's `/storepass/i` and `/keypass/i` patterns are that rule made
  executable, with a planted-snippet case proving they fire.
- **Add a keystore-parsing dependency.** Rejected on the no-new-dependency
  constraint for this probe's runtime surface, and on the boring reason that the
  credential guardrails scan `src/` textually, so anything a dependency exposes
  is outside the only enforcement portcall actually has.
- **Ban the token `pkcs12` in the credential guardrail alongside `storepass`.**
  Rejected: it is the *password*, not the container format, that §4.2 forbids
  touching, and a reader that parses the container has to be able to name it.
  The absence of that pattern is deliberate and is commented as such.
- **Decide the container format from the file name or extension.** Rejected: a
  file called `cacerts` is JKS on one JDK and PKCS#12 on the next, so the name
  is a customer's filesystem, not a fact about the bytes.
- **Best-effort parse of indefinite-length BER.** Rejected: this reader's output
  is a trust-set listing that a verdict is computed from, so a guess is worse
  than a named failure an operator can act on.
- **Report a fully-encrypted store as `no-certificates`.** Rejected: "this store
  is password-protected and portcall supplies none" and "this store was read and
  held nothing" are two different sentences to an operator, and only one of them
  means the cross-check might be missing the anchor being hunted.
- **Commit `keytool`-produced fixture binaries.** Rejected for the boring reason
  that `keytool` and `java` are not available in the sandbox this is built in.
  JKS and PKCS#12 fixtures are generated in-process by `jks-writer.ts` and
  `pkcs12-writer.ts`, consistent with `record-stores.ts`'s existing precedent of
  not committing opaque binary fixtures.

## Consequences

- Java's arm of the cross-check covers only the entries the reader could open,
  and the finding says so out loud rather than grading the readable half as if it
  were the whole store.
- SPEC.md §4.2 can state the sanctioned reads positively — public trust anchors
  via the platform's own command, and runtime trust stores **as files** — and
  cite this record for the second half.
- `java-keystore.ts` may never gain a `node:` import; the caller does the I/O.
- Two low-severity findings were knowingly left open when the reader landed: the
  `MAX_DER_DEPTH` cap is decorative given PKCS#12's fixed schema path, and
  `MAX_KEYSTORE_CERTIFICATES` has no behavioural test. Neither blocks, both are
  on the record.
- The guardrail asserts that `readKeystore(bytes)` is one of the two reads it
  must let through. If a future credential pattern starts flagging it, the probe
  is what breaks, so the constraint is written down as a test rather than as a
  comment.
