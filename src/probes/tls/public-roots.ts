import { X509Certificate } from '@peculiar/x509';
import type { Name } from '@peculiar/x509';

/**
 * Public-root classification (M3, ADR-0002, ADR-0021).
 *
 * The question is only ever "is the anchor of this chain one of the public
 * roots the runtime ships, or something someone installed here". The reference
 * list arrives as PEM strings - `PUBLIC_ROOT_CA_PEMS` in `src/net/root-bundle.ts`,
 * which is the runtime's own bundle - and is passed *in*, never imported here:
 * that file touches `node:tls`, and this one must stay importable by a pure
 * evaluation. Taking the bundle as a parameter also means a test can pin the
 * reference list, and the real one is then just the list the shell happens to
 * pass (`test/tls-public-roots.test.ts` passes the real one on purpose).
 *
 * **Nothing here verifies a signature**, per ADR-0021: `@peculiar/x509` is used
 * to parse and to read names, and its chain-building and verification APIs are
 * out of bounds. That constraint shapes the verdict below, so it is worth
 * being explicit about what each answer is worth:
 *
 * - `public` is claimed on **byte identity** with a bundled root. Bytes cannot
 *   be forged into someone else's certificate, so this needs no signature.
 * - `private` is claimed when the anchor is presented and is not in the bundle,
 *   or when the topmost certificate names an issuer that is not the subject of
 *   *any* bundled root - in which case no public root the runtime ships could
 *   have issued it, whatever the signatures say. Absence of a name match is
 *   conclusive.
 * - `indeterminate` is everything else: the peer did not send its anchor and
 *   the name it points at does exist in the bundle. Presence of a name match is
 *   *not* conclusive - an interception CA can copy a public root's DN into its
 *   issuer field, and only a signature check tells the two apart. So the answer
 *   is "we could not tell", which is a verdict this tool is allowed to give
 *   (ADR-0006) and a false "public" is not.
 */

/** What the anchor of a presented chain is, as far as bytes and names can prove. */
export type RootClass = 'public' | 'private' | 'indeterminate';

/** Why the class was reached. Reported as evidence, so it is a closed vocabulary of our own words. */
export type RootReason =
  | 'bundled-root-on-path'
  | 'self-signed-anchor-not-bundled'
  | 'issuer-matches-no-bundled-root'
  | 'anchor-not-presented';

export interface RootVerdict {
  class: RootClass;
  reason: RootReason;
  /** Index into the presented chain of the bundled root that matched, or `null` when none did. Always on `path`. */
  matchedIndex: number | null;
  /** Indices on the leaf's issuer->subject path, leaf first. Never empty. */
  path: readonly number[];
}

/**
 * Membership questions over the runtime's root bundle. Two of them, because
 * they are worth different amounts: `hasCertificate` is proof, `hasSubject`
 * only rules things out (see the module comment).
 */
export interface PublicRootIndex {
  /** How many roots were indexed. Reported so a reader can see the bundle was not empty. */
  readonly size: number;
  hasCertificate(der: Uint8Array): boolean;
  hasSubject(canonicalSubject: string): boolean;
}

/** Base64 of the DER bytes, used as the identity key. `btoa` is a platform global, not `node:*`. */
function derKey(der: Uint8Array): string {
  let binary = '';
  // Chunked: a certificate is a few kilobytes and `String.fromCharCode(...der)`
  // spreads every byte as an argument, which is a stack overflow waiting for a
  // large chain to arrive.
  for (let offset = 0; offset < der.length; offset += 0x2000) {
    binary += String.fromCharCode(...der.subarray(offset, offset + 0x2000));
  }
  return btoa(binary);
}

/** Trim, collapse runs of whitespace, lowercase: the parts of DN matching that are not encoding. */
function normaliseAttribute(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * A DN reduced to a comparable string.
 *
 * Two encoders will spell the same distinguished name differently - printable
 * string versus UTF-8, `CN=Foo` versus `cn = Foo` - so the comparison runs over
 * the structured form (`Name.toJSON()`), never over `cert.subject`. RDN *order*
 * is kept because it is semantically significant; the attributes inside one
 * multi-valued RDN are sorted, because their order is not.
 */
export function canonicalDn(name: Name): string {
  return name
    .toJSON()
    .map((rdn) =>
      Object.entries(rdn)
        .map(([type, values]) => `${type.toLowerCase()}=${values.map(normaliseAttribute).sort().join('*')}`)
        .sort()
        .join('+'),
    )
    .join(',');
}

/** Index a bundle of PEM roots. Parsing ~150 certificates costs tens of milliseconds; do it once per run. */
export function publicRootIndex(pems: readonly string[]): PublicRootIndex {
  const certificates = new Set<string>();
  const subjects = new Set<string>();

  for (const pem of pems) {
    const root = new X509Certificate(pem);
    certificates.add(derKey(new Uint8Array(root.rawData)));
    subjects.add(canonicalDn(root.subjectName));
  }

  return {
    size: pems.length,
    hasCertificate: (der: Uint8Array): boolean => certificates.has(derKey(der)),
    hasSubject: (canonicalSubject: string): boolean => subjects.has(canonicalSubject),
  };
}

/**
 * The certificates the leaf actually leads to, by index, leaf first.
 *
 * Walking issuer DN to subject DN from `chain[0]` is what separates the chain
 * from the array it arrived in. A peer sends whatever it likes, in whatever
 * order; only the certificates on this path are the ones it claims issued the
 * leaf. The walk reads *names* and nothing else, which is exactly the reading
 * ADR-0021 sanctions - it establishes what the peer claims, never that the
 * claim is signed.
 *
 * Two rules make the walk total on hostile input. A self-signed certificate is
 * the terminus, so it does not link back onto its own subject; and a
 * certificate is visited at most once, so DNs that name each other in a cycle
 * end the walk instead of spinning. When two presented certificates share a
 * subject DN - a cross-signed CA sent under both its issuers - the first
 * unvisited one wins: both are on a legitimate path to the same anchor, and
 * this code cannot tell them apart without the signature check it may not do.
 */
function issuancePath(chain: readonly X509Certificate[]): number[] {
  const subjects = chain.map((certificate) => canonicalDn(certificate.subjectName));
  const issuers = chain.map((certificate) => canonicalDn(certificate.issuerName));
  const path: number[] = [];
  const visited = new Set<number>();

  for (let current = 0; current < chain.length; ) {
    visited.add(current);
    path.push(current);
    const issuer = issuers[current];
    /* c8 ignore next */
    if (issuer === undefined) break;
    if (issuer === subjects[current]) break;
    const next = subjects.findIndex((subject, index) => subject === issuer && !visited.has(index));
    if (next < 0) break;
    current = next;
  }

  return path;
}

/**
 * Classify the anchor of one presented chain, leaf first.
 *
 * The byte match runs over the leaf's issuance path rather than the whole
 * array, and that distinction is the security property. A peer may legitimately
 * present its root anywhere on that path - a cross-signed chain carries the
 * bundled root in the middle, and a runtime that completes the chain from its
 * own store appends it at the end - so the match cannot be pinned to the last
 * element. But bytes that nothing in the chain points at prove nothing about
 * this chain: appending a public root as padding to a privately-rooted chain
 * would otherwise buy a `public` verdict and silence the blocker.
 *
 * The residual, which needs a signature to close and so stays open under
 * ADR-0021: a private CA that *names* a bundled root as its issuer and presents
 * that root still reads `public`. Names and bytes cannot tell that from a
 * genuine chain.
 */
export function classifyRoot(chain: readonly X509Certificate[], roots: PublicRootIndex): RootVerdict {
  const path = issuancePath(chain);

  const onPath = new Set(path);
  for (const [index, certificate] of chain.entries()) {
    if (!onPath.has(index)) continue;
    if (roots.hasCertificate(new Uint8Array(certificate.rawData))) {
      return { class: 'public', reason: 'bundled-root-on-path', matchedIndex: index, path };
    }
  }

  const terminusIndex = path.at(-1);
  const terminus = terminusIndex === undefined ? undefined : chain[terminusIndex];
  /* c8 ignore next */
  if (terminus === undefined) throw new Error('classifyRoot needs at least one certificate');

  const issuer = canonicalDn(terminus.issuerName);
  if (canonicalDn(terminus.subjectName) === issuer) {
    return { class: 'private', reason: 'self-signed-anchor-not-bundled', matchedIndex: null, path };
  }
  if (!roots.hasSubject(issuer)) {
    return { class: 'private', reason: 'issuer-matches-no-bundled-root', matchedIndex: null, path };
  }
  return { class: 'indeterminate', reason: 'anchor-not-presented', matchedIndex: null, path };
}
