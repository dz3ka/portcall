import { rootCertificates } from 'node:tls';

/**
 * The runtime's bundled public root CAs, re-exported as plain data (M3,
 * ADR-0002).
 *
 * The `tls` probe's central question is "is the root of the chain this network
 * presented a public CA, or a private one someone installed" - and answering
 * it needs a reference list of the public roots. Node and Bun both expose one
 * as `tls.rootCertificates`: an array of PEM strings, Mozilla's CA list as the
 * runtime shipped it.
 *
 * Three deliberate properties:
 *
 * 1. **Data, not a live handle.** Strings, never certificate objects the
 *    runtime parsed. The evaluation layer compares bytes it parsed itself, so
 *    the runtime is never both the thing under test and the judge (ADR-0002).
 * 2. **The runtime's list, not a vendored copy.** A root bundle vendored into
 *    this repo would drift, and a stale one would call a genuinely public root
 *    "private" - the single most alarming finding this tool can emit. Shipping
 *    no copy means there is nothing to go stale.
 * 3. **Cross-runtime parity is asserted over the verdict, not the bundle**
 *    (ADR-0031). Node and Bun ship *different* Mozilla snapshots and always
 *    have - 145 roots, 121, 120 across three runtime builds - and no ADR ever
 *    promised otherwise. What must not diverge is the answer: the same chain
 *    classified the same way whichever binary the customer ran. So
 *    `test/net-root-bundle.test.ts` runs portcall's own root evaluation under
 *    both runtimes over committed fixture chains and a fixed reference root
 *    set, and separately asserts that the roots those fixtures anchor in ship
 *    in both bundles - the one difference that would flip a verdict.
 *
 * This module reads no store on disk and no OS trust store: locating and
 * reading *those* is the `truststore` probe's job (M4, SPEC.md 7), and it is a
 * separate question - "which roots does this machine trust" is not "which
 * roots are public".
 */
export const PUBLIC_ROOT_CA_PEMS: readonly string[] = rootCertificates;
