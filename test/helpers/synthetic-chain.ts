import type { webcrypto } from 'node:crypto';
import { SubjectAlternativeNameExtension, X509Certificate, X509CertificateGenerator, cryptoProvider } from '@peculiar/x509';

/**
 * Synthetic certificate chains for the `tls` evaluation tests.
 *
 * The chains are built in-process rather than committed as fixture files
 * because every property under test - a validity window either side of a
 * threshold, a wildcard SAN, an issuer DN that names a root the peer did not
 * send - is a *shape*, and a committed PEM would pin one shape per file plus a
 * regeneration ritual whenever a date moved. `test/fixtures/tls/` stays the
 * committed material for the capture layer, which needs a chain a real
 * `node:tls` server can serve.
 *
 * Every certificate here is signed by the same throwaway P-256 key, including
 * the ones that claim to be issued by someone else. That is deliberate and it
 * is not a shortcut: ADR-0021 forbids the evaluation from verifying a
 * signature at all, so a signature that does not check out is precisely as
 * meaningful to the code under test as one that does. What the tests assert is
 * what the evaluation actually reads - names, dates, SANs and raw bytes.
 */

const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

let keyPair: Promise<webcrypto.CryptoKeyPair> | null = null;

/** One key pair for the whole suite: generation is the only slow part, and no test depends on the key. */
function keys(): Promise<webcrypto.CryptoKeyPair> {
  cryptoProvider.set(crypto);
  keyPair ??= crypto.subtle.generateKey(ALGORITHM, false, ['sign', 'verify']);
  return keyPair;
}

export interface SyntheticCertSpec {
  /** Subject DN, e.g. `CN=api.example.com`. */
  subject: string;
  /** Issuer DN. Defaults to the subject, i.e. a self-signed anchor. */
  issuer?: string;
  notBefore?: Date;
  notAfter?: Date;
  /** dNSName SAN entries. Omitted entirely when absent, so "no SAN extension" is expressible. */
  dnsNames?: readonly string[];
}

const DEFAULT_NOT_BEFORE = new Date('2020-01-01T00:00:00Z');
const DEFAULT_NOT_AFTER = new Date('2030-01-01T00:00:00Z');

let serial = 0;

/** One certificate, as the DER bytes a capture would carry. */
export async function syntheticCert(spec: SyntheticCertSpec): Promise<Uint8Array> {
  const { privateKey, publicKey } = await keys();
  serial += 1;
  const cert = await X509CertificateGenerator.create({
    serialNumber: serial.toString(16).padStart(2, '0'),
    subject: spec.subject,
    issuer: spec.issuer ?? spec.subject,
    notBefore: spec.notBefore ?? DEFAULT_NOT_BEFORE,
    notAfter: spec.notAfter ?? DEFAULT_NOT_AFTER,
    signingKey: privateKey,
    publicKey,
    signingAlgorithm: ALGORITHM,
    extensions:
      spec.dnsNames === undefined
        ? []
        : [new SubjectAlternativeNameExtension(spec.dnsNames.map((value) => ({ type: 'dns' as const, value })))],
  });
  return new Uint8Array(cert.rawData);
}

/** A whole chain, leaf first, in the order a peer presents it. */
export function syntheticChain(specs: readonly SyntheticCertSpec[]): Promise<Uint8Array[]> {
  // Sequential: the serial counter above is shared, and a chain whose members
  // collide on serial would be a confusing thing to debug for no gain.
  return specs.reduce<Promise<Uint8Array[]>>(
    async (soFar, spec) => [...(await soFar), await syntheticCert(spec)],
    Promise.resolve([]),
  );
}

/** The DER behind a PEM, for the certificates that arrive as PEM (`PUBLIC_ROOT_CA_PEMS`, `test/fixtures/tls/`). */
export function derOfPem(pem: string): Uint8Array {
  return new Uint8Array(new X509Certificate(pem).rawData);
}

/** The subject DN string of a PEM certificate, for building a leaf that claims to be issued by it. */
export function subjectOfPem(pem: string): string {
  return new X509Certificate(pem).subject;
}
