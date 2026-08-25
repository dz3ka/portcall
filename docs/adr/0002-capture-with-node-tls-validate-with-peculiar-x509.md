# ADR-0002: Capture with `node:tls`, validate with `@peculiar/x509`

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

The `tls` probe (SPEC.md §7) connects with certificate verification
*deliberately disabled*, because the goal is to observe what a middlebox
presents rather than to decide whether to trust it. Getting that chain requires
a real TLS client talking to a real corporate proxy, which is I/O and is
unavoidably runtime-specific.

Deciding what the chain *means* is a different job: is the root public or
private, who issued it, how deep is the chain, has the leaf expired, does it
match the SNI, and is the chain seen through the proxy different from the one
seen directly. That is pure computation over the certificate bytes, it is the
part a reviewer will actually scrutinise, and it is the part that has to be
testable against recorded fixtures rather than against a live network.

There is a second force. The tool ships compiled with Bun and also runs under
Node (ADR-0001). If the evaluation reads the *runtime's* certificate objects —
`tls.PeerCertificate`, `node:crypto`'s `X509Certificate` — then the answers it
gives depend on which runtime executed, and a fixture suite proves the behaviour
of only one of the two shipping paths.

## Decision

Split capture from validation.

`node:tls` captures and nothing more: open the connection, record the negotiated
protocol version and cipher, and take the presented chain as raw DER. No
interpretation happens at that layer.

`@peculiar/x509` parses and evaluates that DER inside a pure function of
`(chain, profile) => Finding[]`. No evaluation code reads a runtime certificate
object. Fixtures are committed DER chains — public, intercepted, expired,
wrong-SNI — so the interesting logic is exercised without a network at all.

The dependency itself lands at M3 with the probe. The decision is recorded now
because it is what makes the M0 finding model and the fixture format the right
shape: evidence carries observed values, not runtime objects.

## Alternatives considered

- **Evaluate with Node's `X509Certificate` / `tls.PeerCertificate`.** Rejected:
  the runtime is part of what is under test. Using its own certificate parser to
  judge a chain makes "the validation logic is identical under Bun and Node"
  unfalsifiable, and that claim is where this project's credibility sits.
- **Shell out to `openssl s_client` and `openssl x509`.** Rejected for the
  boring reason: this runs on a customer's laptop, where there may be no
  `openssl`, an ancient one, or one the endpoint policy will not let us spawn.
  It also adds a subprocess to the list of things a security team has to reason
  about, in a tool whose selling point is that the list is short.
- **Turn verification on and read the resulting error.** Rejected: that error is
  the useless message (`self-signed certificate in certificate chain`) this whole
  project exists to replace, and a failed handshake often means never seeing the
  chain that would have explained it.
- **Hand-roll ASN.1/DER parsing.** Rejected: certificate parsing is a classic
  source of subtle bugs, it is not the part of this tool anyone is paying
  attention to, and writing it wins nothing a maintained library does not
  already give.

## Consequences

One runtime dependency is added at M3. It is WebCrypto-based with no native
code, which keeps ADR-0001's single-runner cross-compile intact.

The capture layer stays thin, which is the point: the code that is hard to test
does almost nothing, and the code that does the reasoning needs no network. The
price is that a chain is serialised to DER and parsed again rather than reusing
the object the runtime already built — microseconds, on a path that just spent a
round trip.

Re-open if `@peculiar/x509` cannot express something the probe needs, such as
name-constraint evaluation. The fallback there is a vendored parser, not a
retreat to the runtime's own certificate object.
