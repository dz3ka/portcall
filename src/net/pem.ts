/**
 * PEM in, DER out and back again - the one base64 chunking routine in the repo
 * (M4). Three readers need it: the OS store reader's `pem-stream` branch, its
 * `base64-der-lines` branch, and the runtime store readers, whose keystores
 * hand back raw DER that has to become a PEM string before it can be compared
 * with anything else.
 *
 * Pure text. Nothing here parses a certificate, checks a signature or decides
 * trust: the repo's certificate identity is byte identity over exactly these
 * strings (ADR-0021), so this module's whole job is to make "the same
 * certificate" produce the same string no matter which tool printed it - CRLF
 * or LF, wrapped at 64 or at 76, indented or not, with or without the
 * `Certificate:` preamble `openssl` and friends like to emit.
 *
 * Two deliberate refusals:
 *
 * 1. **Only `CERTIFICATE` blocks come back.** A `PRIVATE KEY` block in the
 *    input is dropped, not returned and not reported. Portcall never reads
 *    private keys (SPEC.md 4.2); a parser that would hand one to its caller if
 *    a store happened to contain one is a parser that has to be trusted rather
 *    than checked.
 * 2. **A block whose body is not base64 is dropped rather than repaired.** A
 *    half-decoded certificate downstream would be a wrong answer to the most
 *    alarming question this tool asks ("is this root one you installed?"), so
 *    unreadable input becomes no input.
 */

/** RFC 7468 wraps at 64 characters; every tool that reads PEM accepts it. */
const PEM_LINE_LENGTH = 64;

const BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----';
const END_CERTIFICATE = '-----END CERTIFICATE-----';

/**
 * The body character class excludes `-`, so a match can never span the
 * delimiter of an adjacent block of another type: a `PRIVATE KEY` block sitting
 * between two certificates ends the run rather than being swallowed into one.
 */
const CERTIFICATE_BLOCK = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----/g;

/** Canonical base64: no whitespace left, padded to a multiple of four. */
const BASE64_BODY = /^[A-Za-z0-9+/]+={0,2}$/;

/** Base64 with no whitespace and correct padding, or `null`. Never throws. */
export function normaliseBase64(text: string): string | null {
  const body = text.replace(/\s+/g, '');
  if (body.length === 0 || body.length % 4 !== 0) return null;
  if (!BASE64_BODY.test(body)) return null;
  return body;
}

/** DER bytes as a PEM certificate block, wrapped at 64, newline-terminated. */
export function derToPem(der: Uint8Array): string {
  const body = Buffer.from(der).toString('base64');
  const lines: string[] = [];
  for (let offset = 0; offset < body.length; offset += PEM_LINE_LENGTH) {
    lines.push(body.slice(offset, offset + PEM_LINE_LENGTH));
  }
  return `${BEGIN_CERTIFICATE}\n${lines.join('\n')}\n${END_CERTIFICATE}\n`;
}

/**
 * Every `CERTIFICATE` block in `text`, in the order it appeared, each rebuilt
 * through `derToPem`'s exact layout. Rebuilding rather than slicing is the
 * point: two stores that print the same certificate differently must produce
 * the same string here, or byte identity stops being a usable comparison.
 */
export function pemBlocks(text: string): string[] {
  const blocks: string[] = [];
  for (const match of text.matchAll(CERTIFICATE_BLOCK)) {
    const body = normaliseBase64(match[1] ?? '');
    if (body === null) continue;
    blocks.push(derToPem(Buffer.from(body, 'base64')));
  }
  return blocks;
}
