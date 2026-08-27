import { X509Certificate } from '@peculiar/x509';
import type { Name } from '@peculiar/x509';

/**
 * A certificate set, indexed for membership questions (M3, ADR-0021; moved here
 * in M4).
 *
 * Two probes now ask the same two questions of a set of PEMs - "are these exact
 * bytes in it" and "is this subject DN in it". The `tls` probe asks them of the
 * runtime's bundled public roots (`PUBLIC_ROOT_CA_PEMS` in
 * `src/net/root-bundle.ts`); the `truststore` probe asks them of what the OS
 * store actually holds. The set always arrives as a parameter and is never
 * imported here: `root-bundle.ts` touches `node:tls`, and this module must stay
 * importable by a pure evaluation. Taking it as a parameter also lets a test pin
 * the reference list, and the real one is then just the list the shell happens
 * to pass.
 *
 * **Nothing here verifies a signature**, per ADR-0021: `@peculiar/x509` is used
 * to parse and to read names, and its chain-building and verification APIs are
 * out of bounds. That is why there are two questions rather than one, and why
 * they are worth different amounts - see `probes/tls/public-roots.ts`, which
 * turns the answers into a verdict.
 */

/**
 * Membership questions over an indexed certificate set. Two of them, because
 * they are worth different amounts: `hasCertificate` is proof of identity,
 * `hasSubject` only rules things out.
 */
export interface CertificateIndex {
  /** How many certificates were indexed. Reported so a reader can see the set was not empty. */
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

/** Index a set of PEM certificates. Parsing ~150 of them costs tens of milliseconds; do it once per run. */
export function certificateIndex(pems: readonly string[]): CertificateIndex {
  const certificates = new Set<string>();
  const subjects = new Set<string>();

  for (const pem of pems) {
    const certificate = new X509Certificate(pem);
    certificates.add(derKey(new Uint8Array(certificate.rawData)));
    subjects.add(canonicalDn(certificate.subjectName));
  }

  return {
    size: pems.length,
    hasCertificate: (der: Uint8Array): boolean => certificates.has(derKey(der)),
    hasSubject: (canonicalSubject: string): boolean => subjects.has(canonicalSubject),
  };
}
