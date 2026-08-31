/**
 * A hand-rolled reader for Java's `cacerts` container, JKS *and* PKCS#12 (M4,
 * D8/ADR-0036). Pure: bytes in, DER out. No `node:` import anywhere in this
 * file - `readKeystore` takes a `Uint8Array` and nothing else, so it is
 * fixture-testable without a filesystem and the `x509-parse-only` guardrail's
 * node-import ban would hold here even if this file were ever added to its
 * scanned directories.
 *
 * Zero cryptography. This module never verifies a JKS integrity MAC, never
 * decrypts a PKCS#12 `encryptedData` bag and never supplies a password -
 * SPEC.md 4.2 forbids portcall from authenticating at all, and ADR-0036 is the
 * decision that a keystore password is a credential like any other. A
 * `PrivateKeyEntry`'s encrypted key blob (JKS) and a `keyBag`/
 * `pkcs8ShroudedKeyBag` (PKCS#12) are skipped **by length**, never opened:
 * only a `TrustedCertEntry` (JKS) or a `certBag` holding an `x509Certificate`
 * (PKCS#12) is ever returned. The certificate chain that rides along a
 * `PrivateKeyEntry` is plain DER too, and is still skipped - D8's ruling
 * extracts `TrustedCertEntry` material only, so there is exactly one path a
 * certificate can reach the caller by.
 *
 * Format is decided by the first bytes, never by a file name: `FEEDFEED` is
 * JKS, `CECECECE` is JCEKS (a second, sealed-key format no default `cacerts`
 * uses - reported `unsupported-format`, not parsed), a DER `SEQUENCE` header
 * is PKCS#12, anything else is `unsupported-format`. Indefinite-length BER
 * inside a PKCS#12 walk is `unsupported-encoding`, not a best-effort parse.
 *
 * Bounded by construction: every length is checked against the remaining
 * buffer before it is used, DER nesting is capped at `MAX_DER_DEPTH`, and the
 * certificate count is capped at `MAX_KEYSTORE_CERTIFICATES` - once reached,
 * the walk simply stops collecting rather than failing, so a hostile keystore
 * with an unbounded entry count costs a bounded read, not a failed one.
 *
 * `readKeystore` never throws: a malformed, truncated or merely unexpected
 * keystore is a `KeystoreFailure`, exactly like every other seam in
 * `net/types.ts` (ADR-0008 - data out, never an `Error`).
 */

export type KeystoreFormat = 'jks' | 'pkcs12';

export type KeystoreFailure =
  | 'unsupported-format' // magic is neither FEEDFEED nor a DER SEQUENCE (JCEKS lands here)
  | 'unsupported-encoding' // indefinite-length BER, or DER nested past MAX_DER_DEPTH
  | 'truncated' // a length field runs past the buffer, or the entry stream desynchronised
  | 'encrypted' // every cert bag sits inside PKCS#7 encryptedData; no password is ever supplied
  | 'no-certificates'; // parsed cleanly, nothing extractable in it

export interface KeystoreRead {
  format: KeystoreFormat | null;
  /** DER, in file order. Empty exactly when `failure` is non-null. */
  certificates: readonly Uint8Array[];
  /** True when some bags were read and others were encrypted (PKCS#12 only). */
  partial: boolean;
  failure: KeystoreFailure | null;
}

/** DER nesting cap for the PKCS#12 TLV walk. JKS has no nesting to bound. */
export const MAX_DER_DEPTH = 16;

/** Once this many certificates are collected, the walk stops rather than growing the array. */
export const MAX_KEYSTORE_CERTIFICATES = 4096;

const JKS_MAGIC = 0xfeedfeed;
const JCEKS_MAGIC = 0xcececece;

const JKS_PRIVATE_KEY_TAG = 1;
const JKS_TRUSTED_CERT_TAG = 2;

/** One error class, internal to this module: every parse failure throws one and `readKeystore` catches it. */
class KeystoreParseError extends Error {
  readonly reason: KeystoreFailure;

  constructor(reason: KeystoreFailure) {
    super(reason);
    this.name = 'KeystoreParseError';
    this.reason = reason;
  }
}

function failureResult(format: KeystoreFormat | null, reason: KeystoreFailure): KeystoreRead {
  return { format, certificates: [], partial: false, failure: reason };
}

/** Big-endian uint32 at `offset`. Throws `truncated` rather than reading past the buffer. */
function readUint32(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) throw new KeystoreParseError('truncated');
  const b0 = bytes[offset] as number;
  const b1 = bytes[offset + 1] as number;
  const b2 = bytes[offset + 2] as number;
  const b3 = bytes[offset + 3] as number;
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

/** Big-endian uint16 at `offset`. Throws `truncated` rather than reading past the buffer. */
function readUint16(bytes: Uint8Array, offset: number): number {
  if (offset + 2 > bytes.length) throw new KeystoreParseError('truncated');
  const b0 = bytes[offset] as number;
  const b1 = bytes[offset + 1] as number;
  return (b0 << 8) | b1;
}

/** `offset + length`, bounds-checked - the one move every skip-by-length step makes. */
function advance(bytes: Uint8Array, offset: number, length: number): number {
  const next = offset + length;
  if (length < 0 || next > bytes.length) throw new KeystoreParseError('truncated');
  return next;
}

// ---------------------------------------------------------------------------
// JKS: a flat length-prefixed record stream. No nesting, no ASN.1.
//
//   magic(4) version(4) count(4)
//   count * { tag(4) alias(UTF) timestamp(8)
//             tag==1: encryptedKeyLen(4) encryptedKey(n) chainLen(4)
//                     chainLen * { certType(UTF) certLen(4) cert(n) }   -- skipped, not extracted
//             tag==2: certType(UTF) certLen(4) cert(n)                 -- extracted
//           }
//   [20-byte SHA-1 MAC, never checked - checking it needs the password]
//
// A `UTF` value is a 2-byte big-endian byte-length prefix followed by that
// many bytes of (modified) UTF-8. Nothing here decodes one: every UTF field
// in this stream (the alias, each chain entry's cert type) is skipped by its
// declared length, because nothing downstream needs its text.
// ---------------------------------------------------------------------------

function parseJks(bytes: Uint8Array): KeystoreRead {
  let offset = advance(bytes, 4, 4); // magic (already matched by the caller), then version
  const count = readUint32(bytes, offset);
  offset += 4;

  const certificates: Uint8Array[] = [];

  for (let entry = 0; entry < count && certificates.length < MAX_KEYSTORE_CERTIFICATES; entry += 1) {
    const tag = readUint32(bytes, offset);
    offset += 4;
    const aliasLen = readUint16(bytes, offset);
    offset += 2;
    offset = advance(bytes, offset, aliasLen); // alias text, unused
    offset = advance(bytes, offset, 8); // creation timestamp, unused

    if (tag === JKS_PRIVATE_KEY_TAG) {
      const keyLen = readUint32(bytes, offset);
      offset += 4;
      offset = advance(bytes, offset, keyLen); // encrypted key blob: skipped by length, never decoded
      const chainLen = readUint32(bytes, offset);
      offset += 4;
      for (let link = 0; link < chainLen; link += 1) {
        const typeLen = readUint16(bytes, offset);
        offset += 2;
        offset = advance(bytes, offset, typeLen); // "X.509", unused
        const certLen = readUint32(bytes, offset);
        offset += 4;
        // Plain DER, same as a TrustedCertEntry's - and still not extracted.
        // D8's ruling is TrustedCertEntry only; a chain riding a private key
        // gets exactly the key blob's treatment.
        offset = advance(bytes, offset, certLen);
      }
    } else if (tag === JKS_TRUSTED_CERT_TAG) {
      const typeLen = readUint16(bytes, offset);
      offset += 2;
      offset = advance(bytes, offset, typeLen); // "X.509", unused
      const certLen = readUint32(bytes, offset);
      offset += 4;
      const certStart = offset;
      offset = advance(bytes, offset, certLen);
      certificates.push(bytes.slice(certStart, certStart + certLen));
    } else {
      // Neither tag JKS defines: the stream has desynchronised, and any
      // further offset from here would be a guess, not a read.
      throw new KeystoreParseError('truncated');
    }
  }

  return {
    format: 'jks',
    certificates,
    partial: false,
    failure: certificates.length === 0 ? 'no-certificates' : null,
  };
}

// ---------------------------------------------------------------------------
// PKCS#12: a generic DER TLV walker plus one fixed path (RFC 7292), definite
// lengths only.
//
//   PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData OPTIONAL }
//   ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY OPTIONAL }
//   AuthenticatedSafe ::= SEQUENCE OF ContentInfo   -- the authSafe's unwrapped content
//   SafeContents ::= SEQUENCE OF SafeBag            -- an inner ContentInfo's unwrapped content
//   SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, bagAttributes SET OPTIONAL }
//   CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
//
// A `ContentInfo` whose `contentType` is id-data (1.2.840.113549.1.7.1) wraps
// its payload in a plain OCTET STRING; one whose `contentType` is
// id-encryptedData (1.2.840.113549.1.7.6) is not unwrapped at all - no
// password is ever supplied (ADR-0036) - and is reported as such. This can
// happen at the outer `authSafe` (the whole store is encrypted) or at any
// inner `ContentInfo` inside the `AuthenticatedSafe` (that one `SafeContents`
// is encrypted; siblings may still be plain, which is what `partial` reports).
// ---------------------------------------------------------------------------

const TAG_SEQUENCE = 0x30;
const TAG_INTEGER = 0x02;
const TAG_OBJECT_IDENTIFIER = 0x06;
const TAG_OCTET_STRING = 0x04;
/** `[0] EXPLICIT`, constructed, context-specific class - the wrapper every `content`/`bagValue`/`certValue` uses. */
const TAG_CONTEXT_0 = 0xa0;

/** 1.2.840.113549.1.7.1 - id-data. */
const OID_DATA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
/** 1.2.840.113549.1.7.6 - id-encryptedData. */
const OID_ENCRYPTED_DATA = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06]);
/** 1.2.840.113549.1.12.10.1.3 - certBag. */
const OID_CERT_BAG = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03]);
/** 1.2.840.113549.1.9.22.1 - x509Certificate (a CertBag's `certId`). */
const OID_X509_CERTIFICATE = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01]);

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let index = 0; index < a.length; index += 1) if (a[index] !== b[index]) return false;
  return true;
}

/** A parsed TLV's tag and the bounds of its *content* (never including the header). */
interface Tlv {
  tag: number;
  start: number;
  end: number;
}

/** Definite-length only. `0x80` (indefinite) and a length needing more than 4 bytes both fail closed. */
function readLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
  if (offset >= bytes.length) throw new KeystoreParseError('truncated');
  const first = bytes[offset] as number;
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  if (first === 0x80) throw new KeystoreParseError('unsupported-encoding'); // indefinite-length BER
  const lengthBytes = first & 0x7f;
  if (lengthBytes === 0 || lengthBytes > 4) throw new KeystoreParseError('unsupported-encoding');
  if (offset + 1 + lengthBytes > bytes.length) throw new KeystoreParseError('truncated');
  let length = 0;
  for (let index = 0; index < lengthBytes; index += 1) length = length * 256 + (bytes[offset + 1 + index] as number);
  return { length, next: offset + 1 + lengthBytes };
}

/** One tag-length-value at `offset`. `depth` is the caller's nesting count; past `MAX_DER_DEPTH` fails closed. */
function readTlv(bytes: Uint8Array, offset: number, depth: number): Tlv {
  if (depth > MAX_DER_DEPTH) throw new KeystoreParseError('unsupported-encoding');
  if (offset >= bytes.length) throw new KeystoreParseError('truncated');
  const tag = bytes[offset] as number;
  const { length, next } = readLength(bytes, offset + 1);
  const end = next + length;
  if (end > bytes.length) throw new KeystoreParseError('truncated');
  return { tag, start: next, end };
}

/**
 * `ci`'s unwrapped `content` OCTET STRING, when `contentType` is id-data.
 * Throws `encrypted` for id-encryptedData and `unsupported-format` for any
 * other OID or shape - this container reader recognises exactly the one
 * ContentInfo shape PKCS#12 tooling emits for an unencrypted AuthenticatedSafe
 * or SafeContents.
 */
function readContentInfoOctets(bytes: Uint8Array, ci: Tlv, depth: number): Uint8Array {
  const oid = readTlv(bytes, ci.start, depth);
  if (oid.tag !== TAG_OBJECT_IDENTIFIER) throw new KeystoreParseError('unsupported-format');
  const oidBytes = bytes.slice(oid.start, oid.end);
  if (bytesEqual(oidBytes, OID_ENCRYPTED_DATA)) throw new KeystoreParseError('encrypted');
  if (!bytesEqual(oidBytes, OID_DATA)) throw new KeystoreParseError('unsupported-format');
  const wrapper = readTlv(bytes, oid.end, depth);
  if (wrapper.tag !== TAG_CONTEXT_0) throw new KeystoreParseError('unsupported-format');
  const octet = readTlv(bytes, wrapper.start, depth + 1);
  if (octet.tag !== TAG_OCTET_STRING) throw new KeystoreParseError('unsupported-format');
  return bytes.slice(octet.start, octet.end);
}

/**
 * The DER of the certificate inside `bag`, when it is a `certBag` holding an
 * `x509Certificate`, or `null` for every other bag shape - `keyBag`,
 * `pkcs8ShroudedKeyBag`, `secretBag`, an `sdsiCertificate`. A private key
 * inside a PKCS#12 `SafeBag` gets exactly the JKS `PrivateKeyEntry`
 * treatment: recognised by shape, skipped, never opened.
 */
function extractCertFromBag(bytes: Uint8Array, bag: Tlv, depth: number): Uint8Array | null {
  const bagId = readTlv(bytes, bag.start, depth);
  if (bagId.tag !== TAG_OBJECT_IDENTIFIER) throw new KeystoreParseError('truncated');
  const bagValueWrapper = readTlv(bytes, bagId.end, depth);
  if (bagValueWrapper.tag !== TAG_CONTEXT_0) throw new KeystoreParseError('truncated');
  if (!bytesEqual(bytes.slice(bagId.start, bagId.end), OID_CERT_BAG)) return null;

  const certBag = readTlv(bytes, bagValueWrapper.start, depth + 1);
  if (certBag.tag !== TAG_SEQUENCE) throw new KeystoreParseError('truncated');
  const certId = readTlv(bytes, certBag.start, depth + 2);
  if (certId.tag !== TAG_OBJECT_IDENTIFIER) throw new KeystoreParseError('truncated');
  if (!bytesEqual(bytes.slice(certId.start, certId.end), OID_X509_CERTIFICATE)) return null;

  const certValueWrapper = readTlv(bytes, certId.end, depth + 2);
  if (certValueWrapper.tag !== TAG_CONTEXT_0) throw new KeystoreParseError('truncated');
  const certOctet = readTlv(bytes, certValueWrapper.start, depth + 3);
  if (certOctet.tag !== TAG_OCTET_STRING) throw new KeystoreParseError('truncated');
  return bytes.slice(certOctet.start, certOctet.end);
}

function parsePkcs12(bytes: Uint8Array): KeystoreRead {
  const pfx = readTlv(bytes, 0, 0);
  if (pfx.tag !== TAG_SEQUENCE) throw new KeystoreParseError('unsupported-format');
  const version = readTlv(bytes, pfx.start, 1);
  if (version.tag !== TAG_INTEGER) throw new KeystoreParseError('unsupported-format');
  const authSafeCi = readTlv(bytes, version.end, 1);
  if (authSafeCi.tag !== TAG_SEQUENCE) throw new KeystoreParseError('unsupported-format');
  // Throws `encrypted` directly when the whole store is wrapped - a shape no
  // runner has shown, but PKCS#12 tooling permits it (D8's defensive branch).
  const authSafeBytes = readContentInfoOctets(bytes, authSafeCi, 2);

  const safeSeq = readTlv(authSafeBytes, 0, 3);
  if (safeSeq.tag !== TAG_SEQUENCE) throw new KeystoreParseError('truncated');

  const certificates: Uint8Array[] = [];
  let sawEncrypted = false;

  let pos = safeSeq.start;
  while (pos < safeSeq.end && certificates.length < MAX_KEYSTORE_CERTIFICATES) {
    const ci = readTlv(authSafeBytes, pos, 4);
    if (ci.tag !== TAG_SEQUENCE) throw new KeystoreParseError('truncated');
    pos = ci.end;

    let safeContents: Uint8Array;
    try {
      safeContents = readContentInfoOctets(authSafeBytes, ci, 5);
    } catch (error) {
      if (error instanceof KeystoreParseError && error.reason === 'encrypted') {
        sawEncrypted = true;
        continue;
      }
      throw error;
    }

    const bagsSeq = readTlv(safeContents, 0, 6);
    if (bagsSeq.tag !== TAG_SEQUENCE) throw new KeystoreParseError('truncated');
    let bagPos = bagsSeq.start;
    while (bagPos < bagsSeq.end && certificates.length < MAX_KEYSTORE_CERTIFICATES) {
      const bag = readTlv(safeContents, bagPos, 7);
      if (bag.tag !== TAG_SEQUENCE) throw new KeystoreParseError('truncated');
      bagPos = bag.end;
      const cert = extractCertFromBag(safeContents, bag, 8);
      if (cert !== null) certificates.push(cert);
    }
  }

  // Every bag sat inside encryptedData and nothing was extracted: this store
  // has no readable content at all, which is the outcome ADR-0036 names
  // `encrypted`, not a `no-certificates` store that merely happens to be empty.
  if (certificates.length === 0 && sawEncrypted) throw new KeystoreParseError('encrypted');

  return {
    format: 'pkcs12',
    certificates,
    partial: sawEncrypted && certificates.length > 0,
    failure: certificates.length === 0 ? 'no-certificates' : null,
  };
}

/** Never throws: a malformed keystore is a `KeystoreFailure`, not an exception. */
export function readKeystore(bytes: Uint8Array): KeystoreRead {
  if (bytes.length < 4) return failureResult(null, 'unsupported-format');
  const magic = readUint32(bytes, 0);
  if (magic === JKS_MAGIC) return tryParse('jks', () => parseJks(bytes));
  if (magic === JCEKS_MAGIC) return failureResult(null, 'unsupported-format');
  if (bytes[0] === TAG_SEQUENCE) return tryParse('pkcs12', () => parsePkcs12(bytes));
  return failureResult(null, 'unsupported-format');
}

/** Runs one format's parser, turning any `KeystoreParseError` - or anything unforeseen - into a `KeystoreRead`. */
function tryParse(format: KeystoreFormat, parse: () => KeystoreRead): KeystoreRead {
  try {
    return parse();
  } catch (error) {
    if (error instanceof KeystoreParseError) return failureResult(format, error.reason);
    // Defensive, and the reason `readKeystore` can promise never to throw even
    // on a shape this walker did not anticipate: an unexpected exception here
    // means the bytes stopped making sense, which is what `truncated` means to
    // a caller of this function.
    return failureResult(format, 'truncated');
  }
}
