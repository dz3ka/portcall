# TLS fixtures

Two sets, for two layers. `*.pem` serves a live loopback handshake; `chains/*.json` is the
recorded chain material SPEC.md §10 asks for.

## The loopback handshake (`*.pem`)

A throwaway certificate chain for `test/net-tls-capture.test.ts`, which stands up a
loopback TLS server and captures the chain it presents.

- `ca.cert.pem` — a self-signed root, `CN=Portcall Test Fixture Root`. Its **private key was
  discarded at generation time** and is not in this repo: nothing can ever be issued under
  this root again.
- `leaf.cert.pem` — `CN=portcall.test`, `subjectAltName=DNS:portcall.test`, signed by that root.
- `leaf.key.pem` — the leaf's private key. It exists only so a `node:tls` server in the test
  suite can complete a handshake against 127.0.0.1. It is not a credential for anything: it
  is published in a public repo, it belongs to a name that resolves nowhere, and no code
  outside `test/` reads it.

The chain is deliberately shaped like a corporate interception proxy's — a leaf under a
private root — because capturing that chain *successfully*, instead of failing the handshake
on it, is the behaviour SPEC.md §7 and ADR-0002 require of the capture layer.

Both certificates are dated out to 2126 so the suite does not start failing on an expiry
that has nothing to do with what it tests. Regenerate with `openssl` if a future check needs
a different shape; do not add the root's private key back.

## Recorded chains (`chains/*.json`)

The four conditions SPEC.md §10 names — `public`, `intercepted`, `expired`, `wrong-sni` — one
JSON file each, base64-DER inside JSON (design decision D6). `test/tls-recorded-chains.test.ts`
replays them through the `tls` probe and asserts the exact finding id and severity each one has
to produce; `recorded-chains.ts` is the loader those tests import.

A file is one *observation of an endpoint*, not one certificate: it carries the `direct` capture
and, for `intercepted`, the capture taken through the proxy as well, because "the proxied path
presents a different leaf" is a claim about a pair. `capturedAt` travels with it because the
expiry verdicts are a function of a clock — the test injects that instant as `now`, so an
expired certificate stays expired rather than one that expired longer ago every day.

| file | what it is |
| --- | --- |
| `public.json` | a leaf issued in the name of a root this runtime bundles, presented with that root |
| `intercepted.json` | the same public chain direct, and a different leaf re-signed under `CN=Acme Corp TLS Interception CA` through the proxy |
| `expired.json` | a publicly rooted chain whose leaf expired the day before the capture |
| `wrong-sni.json` | a publicly rooted, in-date chain whose only dNSName covers `other.example.net` |

**How they were generated.** `node test/fixtures/tls/record-chains.ts`, which mints the
certificates with `test/helpers/synthetic-chain.ts` and takes the public anchor from the
runtime's own bundled Mozilla list (`src/net/root-bundle.ts`). No network, no `openssl`, no
recording off a real endpoint. The public anchor is a *real* public root because
`tls.public-root` is decided on byte identity against that bundle and never on a signature
(ADR-0021), so a root that merely looks right would prove nothing. If a future runtime stops
shipping it, `test/tls-recorded-chains.test.ts` fails by name and says to re-record.
Regenerating rewrites every byte — fresh keys, fresh serials — so do it when a fixture's shape
must change, not as routine hygiene.

**Why committing them leaks nothing.** The same discipline as the PEMs above, and one addition:

- No private keys, for anything. `synthetic-chain.ts` signs with a **non-extractable** P-256
  key (`crypto.subtle.generateKey(..., false, ...)`) that dies with the recording process, so
  nothing can ever be issued under `CN=api.example.com` or the Acme CA name again — and the
  bytes of that key were never available to be committed in the first place.
- Every name in them is fictional: `api.example.com` and `other.example.net` are RFC 2606
  reserved, and `Acme Corp Ltd` is nobody. No customer, host, address or CA of anyone's is
  recorded here, and no capture from a real network is.
- The one certificate that is not synthetic is a public CA root the runtime already ships to
  every user; it is published by Mozilla and is not a secret in any sense.
