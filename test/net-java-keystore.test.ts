import { describe, expect, it } from 'vitest';
import { MAX_DER_DEPTH, MAX_KEYSTORE_CERTIFICATES, readKeystore } from '../src/net/java-keystore.ts';
import { buildJks, jceksMagicOnly, truncatedJksEntry, truncatedJksMagicOnly } from './helpers/jks-writer.ts';
import {
  buildEncryptedPkcs12,
  buildPkcs12,
  certSafeBag,
  indefiniteLengthPkcs12,
  keySafeBag,
  truncatedPkcs12,
} from './helpers/pkcs12-writer.ts';
import { syntheticCert } from './helpers/synthetic-chain.ts';

/**
 * The hand-rolled JKS/PKCS#12 container reader (M4, WP4, D8/ADR-0036). Every
 * fixture here is built in-process by `jks-writer.ts` / `pkcs12-writer.ts`,
 * never hand-authored binary: the byte stream is the thing under test, so a
 * committed blob would hide exactly what a reader of this file needs to see.
 *
 * `readKeystore` never throws (ADR-0008); every case here asserts on the
 * returned `KeystoreRead`, never on a caught exception.
 */

describe('JKS', () => {
  it('reads a two-cert store', async () => {
    const [certA, certB] = await Promise.all([syntheticCert({ subject: 'CN=Portcall JKS A' }), syntheticCert({ subject: 'CN=Portcall JKS B' })]);
    const bytes = buildJks([
      { kind: 'trusted-cert', alias: 'root-a', certDer: certA },
      { kind: 'trusted-cert', alias: 'root-b', certDer: certB },
    ]);
    const read = readKeystore(bytes);
    expect(read.format).toBe('jks');
    expect(read.failure).toBeNull();
    expect(read.partial).toBe(false);
    expect(read.certificates).toHaveLength(2);
    expect(read.certificates[0]).toEqual(certA);
    expect(read.certificates[1]).toEqual(certB);
  });

  it('skips a PrivateKeyEntry by length - the key blob and its chain never reach `certificates`', async () => {
    const [chainCert, trustedCert] = await Promise.all([
      syntheticCert({ subject: 'CN=Portcall JKS Chain' }),
      syntheticCert({ subject: 'CN=Portcall JKS Trusted' }),
    ]);
    const bytes = buildJks([
      { kind: 'private-key', alias: 'my-key', keyBlob: new Uint8Array([1, 2, 3, 4, 5]), chain: [chainCert] },
      { kind: 'trusted-cert', alias: 'root', certDer: trustedCert },
    ]);
    const read = readKeystore(bytes);
    expect(read.format).toBe('jks');
    expect(read.failure).toBeNull();
    // Only the TrustedCertEntry's cert - not the chain riding the private key.
    expect(read.certificates).toHaveLength(1);
    expect(read.certificates[0]).toEqual(trustedCert);
  });

  it('reports no-certificates for a store with zero entries', () => {
    const read = readKeystore(buildJks([]));
    expect(read.format).toBe('jks');
    expect(read.failure).toBe('no-certificates');
    expect(read.certificates).toEqual([]);
  });

  it('reports truncated when the header is cut off before `version`', () => {
    const read = readKeystore(truncatedJksMagicOnly());
    expect(read.failure).toBe('truncated');
    expect(read.certificates).toEqual([]);
  });

  it('reports truncated when an entry desynchronises mid-record', () => {
    const read = readKeystore(truncatedJksEntry());
    expect(read.failure).toBe('truncated');
  });
});

describe('JCEKS', () => {
  it('reports unsupported-format on the magic alone, format null - never parsed', () => {
    const read = readKeystore(jceksMagicOnly());
    expect(read.format).toBeNull();
    expect(read.failure).toBe('unsupported-format');
    expect(read.certificates).toEqual([]);
  });
});

describe('PKCS#12', () => {
  it('reads an unencrypted store with two certs', async () => {
    const [certA, certB] = await Promise.all([syntheticCert({ subject: 'CN=Portcall PKCS12 A' }), syntheticCert({ subject: 'CN=Portcall PKCS12 B' })]);
    const bytes = buildPkcs12([{ bags: [certSafeBag(certA), certSafeBag(certB)] }]);
    const read = readKeystore(bytes);
    expect(read.format).toBe('pkcs12');
    expect(read.failure).toBeNull();
    expect(read.partial).toBe(false);
    expect(read.certificates).toHaveLength(2);
    expect(read.certificates[0]).toEqual(certA);
    expect(read.certificates[1]).toEqual(certB);
  });

  it('skips a keyBag by shape, never opening its value', async () => {
    const cert = await syntheticCert({ subject: 'CN=Portcall PKCS12 Trusted' });
    const bytes = buildPkcs12([{ bags: [keySafeBag(), certSafeBag(cert)] }]);
    const read = readKeystore(bytes);
    expect(read.failure).toBeNull();
    expect(read.certificates).toHaveLength(1);
    expect(read.certificates[0]).toEqual(cert);
  });

  it('reports encrypted when the whole store is wrapped in encryptedData', () => {
    const read = readKeystore(buildEncryptedPkcs12());
    expect(read.format).toBe('pkcs12');
    expect(read.failure).toBe('encrypted');
    expect(read.certificates).toEqual([]);
    expect(read.partial).toBe(false);
  });

  it('reports partial when one SafeContents is encrypted and a sibling is plain', async () => {
    const cert = await syntheticCert({ subject: 'CN=Portcall PKCS12 Partial' });
    const bytes = buildPkcs12([{ encrypted: true }, { bags: [certSafeBag(cert)] }]);
    const read = readKeystore(bytes);
    expect(read.failure).toBeNull();
    expect(read.partial).toBe(true);
    expect(read.certificates).toHaveLength(1);
    expect(read.certificates[0]).toEqual(cert);
  });

  it('reports no-certificates for a store with an empty SafeContents', () => {
    const read = readKeystore(buildPkcs12([{ bags: [] }]));
    expect(read.failure).toBe('no-certificates');
    expect(read.partial).toBe(false);
  });

  it('reports truncated when the structure is cut off mid-TLV', () => {
    const read = readKeystore(truncatedPkcs12());
    expect(read.failure).toBe('truncated');
  });

  it('reports unsupported-encoding for indefinite-length BER', () => {
    const read = readKeystore(indefiniteLengthPkcs12());
    expect(read.failure).toBe('unsupported-encoding');
  });
});

describe('magic-byte dispatch and never-throws', () => {
  it('reports unsupported-format for an empty buffer', () => {
    const read = readKeystore(new Uint8Array(0));
    expect(read.format).toBeNull();
    expect(read.failure).toBe('unsupported-format');
  });

  it('reports unsupported-format for a single byte', () => {
    const read = readKeystore(new Uint8Array([0xfe]));
    expect(read.format).toBeNull();
    expect(read.failure).toBe('unsupported-format');
  });

  it('reports unsupported-format for bytes matching neither magic', () => {
    const read = readKeystore(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04]));
    expect(read.format).toBeNull();
    expect(read.failure).toBe('unsupported-format');
  });

  it('never throws on random-looking bytes shaped like PKCS#12 but garbage inside', () => {
    const bytes = new Uint8Array([0x30, 0x7f, ...Array.from({ length: 20 }, (_, index) => index)]);
    expect(() => readKeystore(bytes)).not.toThrow();
    const read = readKeystore(bytes);
    expect(read.certificates).toEqual([]);
    expect(read.failure).not.toBeNull();
  });
});

describe('bounds', () => {
  it('exports the depth and count caps used to bound the walk', () => {
    expect(MAX_DER_DEPTH).toBe(16);
    expect(MAX_KEYSTORE_CERTIFICATES).toBe(4096);
  });
});
