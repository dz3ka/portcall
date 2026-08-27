import { X509Certificate } from '@peculiar/x509';
import { PUBLIC_ROOT_CA_PEMS } from '../../../src/net/root-bundle.ts';
import { certificateIndex } from '../../../src/probes/shared/root-index.ts';
import { classifyRoot } from '../../../src/probes/tls/public-roots.ts';
import type { RootClass, RootReason } from '../../../src/probes/tls/public-roots.ts';
import { RECORDED_CONDITIONS, loadRecordedChain } from './recorded-chains.ts';
import type { RecordedCondition } from './recorded-chains.ts';

/**
 * The cross-runtime claim, in the form it can actually be held (ADR-0031).
 *
 * Shipped portcall binaries are compiled with Bun; the test suite runs under
 * Node. What has to be true is that a chain gets the *same verdict* under both
 * - not that the two runtimes ship the same Mozilla bundle, which they do not
 * and never promised to (Node 22 ships 145 roots, Bun 121, Node 24 120; the
 * list diverges Node-to-Node as much as Node-to-Bun).
 *
 * So the reference list here is the roots the *committed* fixtures anchor in,
 * never `PUBLIC_ROOT_CA_PEMS`: pinning the input is what makes the output
 * comparable across two runtimes at all. Both halves of
 * `test/net-root-bundle.test.ts` import this module - the test itself runs it
 * under Node, `print-root-verdicts.ts` runs it under Bun - so one
 * implementation of portcall's own root evaluation is measured twice. That is
 * the point of the exercise: without it, not one line of `certificateIndex` or
 * `classifyRoot` ever executes under the runtime that builds the binary
 * customers run.
 *
 * The residual risk the fixed bundle sets aside is picked back up by
 * `fixtureAnchorsInRuntimeBundle`: a root present in one runtime's bundle and
 * absent from the other would flip `tls.public-root` to `tls.private-root` for
 * the same network, and that is a claim about the runtimes, so it is asserted
 * against the runtimes.
 */

/** Which capture of an endpoint a verdict was reached on. `proxy` exists only for the intercepted fixture. */
type Connection = 'direct' | 'proxy';

/**
 * The reference root set: the anchors the committed chains present, in PEM.
 *
 * Committed bytes only. Taking the runtime's bundle here would put the thing
 * under test on both sides of the comparison and reintroduce exactly the
 * unfixable assertion ADR-0031 retired.
 */
export const FIXTURE_ROOT_PEMS: readonly string[] = fixtureRootPems();

function fixtureRootPems(): string[] {
  /** Keyed by subject so a root shared by several fixtures - all four share ISRG Root X1 - is indexed once. */
  const anchors = new Map<string, string>();

  for (const condition of RECORDED_CONDITIONS) {
    const fixture = loadRecordedChain(condition);
    if (fixture.publicAnchor === null) continue;

    const der = fixture.direct.chainDer.at(-1);
    if (der === undefined) throw new Error(`${condition}: recorded chain is empty`);
    const anchor = new X509Certificate(der);
    if (anchor.subject !== fixture.publicAnchor) {
      throw new Error(`${condition}: last certificate is ${anchor.subject}, not the recorded anchor ${fixture.publicAnchor}`);
    }
    anchors.set(anchor.subject, anchor.toString('pem'));
  }

  if (anchors.size === 0) throw new Error('no recorded chain carries a public anchor');
  return [...anchors.values()];
}

/** One verdict, flattened to JSON-safe scalars so it survives the trip out of a Bun subprocess unchanged. */
export interface CrossRuntimeVerdict {
  readonly condition: RecordedCondition;
  readonly connection: Connection;
  readonly class: RootClass;
  readonly reason: RootReason;
  readonly matchedIndex: number | null;
  readonly path: readonly number[];
}

/**
 * Every committed capture classified against `FIXTURE_ROOT_PEMS`.
 *
 * The whole verdict travels, not just the class: `reason`, `matchedIndex` and
 * `path` are what distinguish "public because the bundled root is on the
 * leaf's issuance path" from "public because a root happened to be in the
 * array" (ADR-0026), and a runtime that agreed on the class while disagreeing
 * on the path would have found a real divergence in `canonicalDn` or the
 * issuance walk.
 */
export function fixtureVerdicts(): CrossRuntimeVerdict[] {
  const roots = certificateIndex(FIXTURE_ROOT_PEMS);
  const verdicts: CrossRuntimeVerdict[] = [];

  for (const condition of RECORDED_CONDITIONS) {
    const fixture = loadRecordedChain(condition);
    const captures = [
      ['direct', fixture.direct],
      ['proxy', fixture.viaProxy],
    ] as const;

    for (const [connection, capture] of captures) {
      if (capture === null) continue;
      const verdict = classifyRoot(
        capture.chainDer.map((der) => new X509Certificate(der)),
        roots,
      );
      verdicts.push({
        condition,
        connection,
        class: verdict.class,
        reason: verdict.reason,
        matchedIndex: verdict.matchedIndex,
        path: verdict.path,
      });
    }
  }

  return verdicts;
}

/**
 * The one claim that is genuinely about the runtimes' own bundles: each root
 * the fixtures anchor in still ships here.
 *
 * Narrow on purpose. The bundles differ in size and always will, but a root
 * that is in Node's list and not in Bun's would classify the same corporate
 * network as publicly rooted for one binary and privately rooted for the other
 * - the divergence that actually reaches a customer. Both runtimes answer this
 * over their own `tls.rootCertificates`, and both answers must be `true`.
 */
export function fixtureAnchorsInRuntimeBundle(): Record<string, boolean> {
  const runtime = certificateIndex(PUBLIC_ROOT_CA_PEMS);
  const present: Record<string, boolean> = {};

  for (const pem of FIXTURE_ROOT_PEMS) {
    const anchor = new X509Certificate(pem);
    present[anchor.subject] = runtime.hasCertificate(new Uint8Array(anchor.rawData));
  }

  return present;
}

/** What `print-root-verdicts.ts` emits and the test parses: both halves of the claim in one object. */
export interface CrossRuntimeReport {
  readonly verdicts: CrossRuntimeVerdict[];
  readonly anchorsInRuntimeBundle: Record<string, boolean>;
}
