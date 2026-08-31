/**
 * Builds JKS bytes in memory, for `test/net-java-keystore.test.ts` (M4, WP4).
 *
 * Not a fixture file: the shape under test is a byte stream
 * (`src/net/java-keystore.ts`'s own comment spells it: magic, version, count,
 * then per entry a tag/alias/timestamp and either a `TrustedCertEntry`'s DER
 * or a `PrivateKeyEntry`'s opaque key blob and chain), and a hand-authored
 * binary fixture would hide exactly the field this helper makes explicit.
 *
 * `keyBlob` is always arbitrary bytes minted here, never a real private key -
 * `readKeystore` skips it by length and this helper does not pretend
 * otherwise by shipping anything that looks like key material.
 */

const JKS_MAGIC = 0xfeedfeed;
const JCEKS_MAGIC = 0xcececece;
const JKS_VERSION = 2;
const TRUSTED_CERT_TAG = 2;
const PRIVATE_KEY_TAG = 1;
const CERT_TYPE = 'X.509';

export interface JksTrustedCertEntry {
  kind: 'trusted-cert';
  alias: string;
  certDer: Uint8Array;
}

export interface JksPrivateKeyEntry {
  kind: 'private-key';
  alias: string;
  /** Arbitrary bytes standing in for an encrypted key. Never decoded by the reader. */
  keyBlob: Uint8Array;
  /** DER certs riding the entry's chain - skipped by length, same as `keyBlob`. */
  chain: readonly Uint8Array[];
}

export type JksEntry = JksTrustedCertEntry | JksPrivateKeyEntry;

function u32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function u16(value: number): Uint8Array {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value, false);
  return bytes;
}

function utf(text: string): Uint8Array {
  const body = new TextEncoder().encode(text);
  return concat(u16(body.length), body);
}

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

/** An 8-byte placeholder creation timestamp; the reader never reads it. */
const TIMESTAMP = new Uint8Array(8);

function trustedCertBytes(entry: JksTrustedCertEntry): Uint8Array {
  return concat(
    u32(TRUSTED_CERT_TAG),
    utf(entry.alias),
    TIMESTAMP,
    utf(CERT_TYPE),
    u32(entry.certDer.length),
    entry.certDer,
  );
}

function privateKeyBytes(entry: JksPrivateKeyEntry): Uint8Array {
  const chainParts = entry.chain.map((certDer) => concat(utf(CERT_TYPE), u32(certDer.length), certDer));
  return concat(
    u32(PRIVATE_KEY_TAG),
    utf(entry.alias),
    TIMESTAMP,
    u32(entry.keyBlob.length),
    entry.keyBlob,
    u32(entry.chain.length),
    ...chainParts,
  );
}

/** A well-formed JKS stream, magic through the last entry. No MAC trailer - the reader never checks one. */
export function buildJks(entries: readonly JksEntry[]): Uint8Array {
  const entryBytes = entries.map((entry) => (entry.kind === 'trusted-cert' ? trustedCertBytes(entry) : privateKeyBytes(entry)));
  return concat(u32(JKS_MAGIC), u32(JKS_VERSION), u32(entries.length), ...entryBytes);
}

/** Magic FEEDFEED with nothing after it - cut off before `version` can be read. */
export function truncatedJksMagicOnly(): Uint8Array {
  return u32(JKS_MAGIC);
}

/** A well-formed header claiming one entry, then nothing - the entry stream is cut off mid-record. */
export function truncatedJksEntry(): Uint8Array {
  return concat(u32(JKS_MAGIC), u32(JKS_VERSION), u32(1), u32(TRUSTED_CERT_TAG), utf('short'));
}

/** The four JCEKS magic bytes and nothing else - `readKeystore` must reject this on the magic alone. */
export function jceksMagicOnly(): Uint8Array {
  return u32(JCEKS_MAGIC);
}
