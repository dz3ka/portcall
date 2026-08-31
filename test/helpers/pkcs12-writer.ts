/**
 * Builds PKCS#12 (PFX) bytes in memory, for `test/net-java-keystore.test.ts`
 * (M4, WP4).
 *
 * **Deviation, disclosed here rather than silently:** the plan's convention
 * for a PKCS#12 fixture is `keytool`, the way `test/truststore-injected/`
 * generates a root. `keytool`/`java` are not installed in this environment
 * (`java -version` fails), so an unencrypted fixture cannot be produced that
 * way here. This writer hand-assembles the same DER shape
 * `src/net/java-keystore.ts`'s own comment documents (PFX -> authSafe
 * ContentInfo(data) -> AuthenticatedSafe -> ContentInfo(data) ->
 * SafeContents -> SafeBag(certBag) -> CertBag -> x509Certificate OCTET
 * STRING), the same way `jks-writer.ts` hand-assembles a JKS stream instead
 * of shelling out to a JDK tool. An `encryptedData` bag never needs real
 * PKCS#7 encryption to exercise this reader: `readContentInfoOctets` decides
 * `encrypted` from the `contentType` OID alone and never opens the wrapper,
 * so the "ciphertext" bytes here are arbitrary and say so.
 */

const TAG_SEQUENCE = 0x30;
const TAG_INTEGER = 0x02;
const TAG_OBJECT_IDENTIFIER = 0x06;
const TAG_OCTET_STRING = 0x04;
const TAG_CONTEXT_0 = 0xa0;

const OID_DATA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
const OID_ENCRYPTED_DATA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06]);
const OID_CERT_BAG = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03]);
const OID_X509_CERTIFICATE = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01]);
/** 1.2.840.113549.1.12.10.1.2 - keyBag. Used only to prove the reader skips it, never decoded here. */
const OID_KEY_BAG = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02]);

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Definite-length DER only, long form past 127 bytes - real certificate DER needs it. */
function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), derLength(content.length), content);
}

/** `[0] EXPLICIT` around one TLV, the wrapper every `content`/`bagValue`/`certValue` uses. */
function explicit0(inner: Uint8Array): Uint8Array {
  return tlv(TAG_CONTEXT_0, inner);
}

/** A `ContentInfo` whose `contentType` is id-data, wrapping `payload` in an OCTET STRING. */
function contentInfoData(payload: Uint8Array): Uint8Array {
  return tlv(TAG_SEQUENCE, concat(tlv(TAG_OBJECT_IDENTIFIER, OID_DATA), explicit0(tlv(TAG_OCTET_STRING, payload))));
}

/**
 * A `ContentInfo` whose `contentType` is id-encryptedData. `readKeystore`
 * throws `encrypted` on the OID alone and never opens `wrapperContent`, so it
 * is a fixed, clearly-synthetic placeholder rather than real PKCS#7 output.
 */
function contentInfoEncrypted(): Uint8Array {
  const wrapperContent = new TextEncoder().encode('portcall fixture: never decoded, contentType alone decides');
  return tlv(TAG_SEQUENCE, concat(tlv(TAG_OBJECT_IDENTIFIER, OID_ENCRYPTED_DATA), explicit0(tlv(TAG_OCTET_STRING, wrapperContent))));
}

/** `SafeBag { bagId: certBag, bagValue: CertBag { certId: x509Certificate, certValue: DER } }`. */
export function certSafeBag(certDer: Uint8Array): Uint8Array {
  const certBag = tlv(
    TAG_SEQUENCE,
    concat(tlv(TAG_OBJECT_IDENTIFIER, OID_X509_CERTIFICATE), explicit0(tlv(TAG_OCTET_STRING, certDer))),
  );
  return tlv(TAG_SEQUENCE, concat(tlv(TAG_OBJECT_IDENTIFIER, OID_CERT_BAG), explicit0(certBag)));
}

/**
 * `SafeBag { bagId: keyBag, bagValue: <opaque> }` - arbitrary bytes standing
 * in for an encrypted private key. The reader recognises this bag only by its
 * `bagId` and skips the value by length; it is never opened here either.
 */
export function keySafeBag(): Uint8Array {
  const opaque = new Uint8Array(32).fill(0xee);
  return tlv(TAG_SEQUENCE, concat(tlv(TAG_OBJECT_IDENTIFIER, OID_KEY_BAG), explicit0(opaque)));
}

export interface Pkcs12ContentSpec {
  /** Plain (`id-data`) `SafeContents` holding these bags, in order. */
  bags?: readonly Uint8Array[];
  /** When true, this `ContentInfo` is `id-encryptedData` instead, and `bags` is ignored. */
  encrypted?: boolean;
}

/**
 * A well-formed, unencrypted-shell PKCS#12: `version=3`, an `authSafe` of
 * `id-data` wrapping one `ContentInfo` per `contents` entry. An entry with
 * `encrypted: true` models one encrypted `SafeContents` sibling among
 * plaintext ones - the `partial` case (D8's "some bags were read and others
 * were encrypted").
 */
export function buildPkcs12(contents: readonly Pkcs12ContentSpec[]): Uint8Array {
  const contentInfos = contents.map((spec) =>
    spec.encrypted === true ? contentInfoEncrypted() : contentInfoData(tlv(TAG_SEQUENCE, concat(...(spec.bags ?? [])))),
  );
  const authenticatedSafe = tlv(TAG_SEQUENCE, concat(...contentInfos));
  const version = tlv(TAG_INTEGER, Uint8Array.of(3));
  return tlv(TAG_SEQUENCE, concat(version, contentInfoData(authenticatedSafe)));
}

/** The whole store's `authSafe` is itself `id-encryptedData` - D8's "defensive branch". */
export function buildEncryptedPkcs12(): Uint8Array {
  const version = tlv(TAG_INTEGER, Uint8Array.of(3));
  return tlv(TAG_SEQUENCE, concat(version, contentInfoEncrypted()));
}

/** A `SEQUENCE` header claiming far more content than follows - cut off mid-structure. */
export function truncatedPkcs12(): Uint8Array {
  return tlv(TAG_SEQUENCE, Uint8Array.of(0x02, 0x01, 0x03)).slice(0, 4);
}

/** A `SEQUENCE` whose length byte is `0x80` - indefinite-length BER, refused outright. */
export function indefiniteLengthPkcs12(): Uint8Array {
  return Uint8Array.of(TAG_SEQUENCE, 0x80, 0x02, 0x01, 0x03);
}
