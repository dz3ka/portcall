import { createHash } from 'node:crypto';

/**
 * Shared by `test/net-root-bundle.test.ts` and its Bun-side sibling
 * (`print-root-fingerprints.ts`) so that both runtimes are measured by the
 * *same* code. A parity test whose two halves each carry their own hashing
 * logic proves nothing about the bundles it claims to compare.
 *
 * Only `node:crypto`'s SHA-256 and base64 decoding are used - both are
 * behaviour Bun implements identically, and neither is what is under test.
 */
const PEM_BODY = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/;

/** Sorted SHA-256 hex digests of each PEM's DER bytes; sorted so order is not part of the claim. */
export function fingerprintsOf(pems: readonly string[]): string[] {
  return pems
    .map((pem) => {
      const body = PEM_BODY.exec(pem)?.[1];
      if (body === undefined) throw new Error('not a PEM certificate');
      return createHash('sha256').update(Buffer.from(body.replace(/\s+/g, ''), 'base64')).digest('hex');
    })
    .sort((a, b) => a.localeCompare(b));
}
