import { writeFileSync } from 'node:fs';
import { PUBLIC_ROOT_CA_PEMS } from '../../../src/net/root-bundle.ts';
import { derOfPem, subjectOfPem, syntheticChain } from '../../helpers/synthetic-chain.ts';
import { recordedChainPath } from './recorded-chains.ts';
import type { RecordedCondition } from './recorded-chains.ts';

/**
 * Regenerates `chains/*.json`, the four recorded chains SPEC.md §10 asks for.
 *
 *     node test/fixtures/tls/record-chains.ts
 *
 * A separate file from `recorded-chains.ts` for the reason
 * `print-root-fingerprints.ts` is separate from `root-fingerprints.ts`: that
 * module is imported by the tests, and a module that writes files on import
 * would rewrite the fixtures every time the suite ran - which is the one thing
 * a committed fixture must not do.
 *
 * Nothing here touches the network. The three publicly-rooted conditions take
 * their anchor from the runtime's own bundled Mozilla list
 * (`src/net/root-bundle.ts`), because `tls.public-root` is decided on byte
 * identity against exactly that list (ADR-0021: no signature is ever checked,
 * so a root that merely *looks* right proves nothing). Everything else is
 * minted by `test/helpers/synthetic-chain.ts` under a non-extractable P-256 key
 * that dies with this process, so no fixture here is a credential and no name
 * in one can ever be signed for again.
 *
 * Regenerating rewrites every byte - fresh keys, fresh serials - so do it when
 * a fixture's *shape* has to change, not as routine hygiene.
 */

/**
 * The instant every fixture claims to have been captured at. Fixed, and
 * recorded in the file: the expiry conditions are a function of a clock, and a
 * fixture whose certificate expired "yesterday" relative to the day the suite
 * runs is not a fixture.
 */
const CAPTURED_AT = new Date('2026-08-26T00:00:00.000Z');

const DAY_MS = 24 * 60 * 60 * 1000;

function daysFromCapture(days: number): Date {
  return new Date(CAPTURED_AT.getTime() + days * DAY_MS);
}

const HOST = 'api.example.com';

/** A fictional appliance, named the way a customer's own would be. Nobody's real CA. */
const PRIVATE_CA = 'CN=Acme Corp TLS Interception CA, O=Acme Corp Ltd, C=GB';

/**
 * Which bundled root to anchor the public chains in.
 *
 * Preference by name rather than `PUBLIC_ROOT_CA_PEMS[0]`: the bundle's order
 * is the runtime's business and could change between releases, while these two
 * roots are the longest-lived, most widely shipped anchors in it. The fallback
 * to the first entry keeps the script working on a runtime that ships neither -
 * the fixture records whichever it picked, and
 * `test/tls-recorded-chains.test.ts` asserts that root is still bundled.
 */
const PREFERRED_ROOTS = ['ISRG Root X1', 'DigiCert Global Root CA'];

function publicRootPem(): string {
  for (const name of PREFERRED_ROOTS) {
    const pem = PUBLIC_ROOT_CA_PEMS.find((candidate) => subjectOfPem(candidate).includes(name));
    if (pem !== undefined) return pem;
  }
  const first = PUBLIC_ROOT_CA_PEMS[0];
  if (first === undefined) throw new Error('this runtime bundles no public roots');
  return first;
}

interface RecordedCaptureFile {
  negotiatedProtocol: string | null;
  negotiatedCipher: string | null;
  requestedSni: string;
  chainDer: string[];
}

interface RecordedChainFile {
  condition: RecordedCondition;
  summary: string;
  capturedAt: string;
  host: string;
  publicAnchor: string | null;
  direct: RecordedCaptureFile;
  viaProxy?: RecordedCaptureFile;
}

/** Base64-DER, one string per certificate, leaf first (design decision D6). */
function capture(chainDer: readonly Uint8Array[], requestedSni = HOST): RecordedCaptureFile {
  return {
    negotiatedProtocol: 'TLSv1.3',
    negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
    requestedSni,
    chainDer: chainDer.map((der) => Buffer.from(der).toString('base64')),
  };
}

interface LeafShape {
  dnsNames?: readonly string[];
  notBefore?: Date;
  notAfter?: Date;
}

/** A leaf issued in the name of the bundled root, with that root presented behind it. */
async function publicChain(leaf: LeafShape = {}): Promise<Uint8Array[]> {
  const pem = publicRootPem();
  const chain = await syntheticChain([
    {
      subject: `CN=${HOST}`,
      issuer: subjectOfPem(pem),
      dnsNames: leaf.dnsNames ?? [HOST],
      notBefore: leaf.notBefore ?? daysFromCapture(-90),
      notAfter: leaf.notAfter ?? daysFromCapture(400),
    },
  ]);
  return [...chain, derOfPem(pem)];
}

async function files(): Promise<RecordedChainFile[]> {
  const anchor = subjectOfPem(publicRootPem());

  const interceptedProxyChain = await syntheticChain([
    {
      subject: `CN=${HOST}`,
      issuer: PRIVATE_CA,
      dnsNames: [HOST],
      // Well clear of the expiry warning window: this fixture is about the
      // anchor, and a short-lived appliance certificate would add a second
      // verdict to the row that has nothing to do with interception.
      notBefore: daysFromCapture(-1),
      notAfter: daysFromCapture(365),
    },
    { subject: PRIVATE_CA, notBefore: daysFromCapture(-800), notAfter: daysFromCapture(800) },
  ]);

  return [
    {
      condition: 'public',
      summary:
        'The endpoint as it looks from an unmanaged network: a leaf issued in the name of a root ' +
        'this runtime bundles, presented with that root, negotiating TLS 1.3.',
      capturedAt: CAPTURED_AT.toISOString(),
      host: HOST,
      publicAnchor: anchor,
      direct: capture(await publicChain()),
    },
    {
      condition: 'intercepted',
      summary:
        'The mitmproxy condition from SPEC.md §10, as a pair: the direct path presents the public ' +
        'chain, the proxied path a different leaf re-signed under an appliance CA no runtime ships.',
      capturedAt: CAPTURED_AT.toISOString(),
      host: HOST,
      publicAnchor: anchor,
      direct: capture(await publicChain()),
      viaProxy: capture(interceptedProxyChain),
    },
    {
      condition: 'expired',
      summary:
        'A publicly rooted chain whose leaf expired the day before the capture, so the expiry ' +
        'verdict is isolated from the root verdict.',
      capturedAt: CAPTURED_AT.toISOString(),
      host: HOST,
      publicAnchor: anchor,
      direct: capture(await publicChain({ notBefore: daysFromCapture(-400), notAfter: daysFromCapture(-1) })),
    },
    {
      condition: 'wrong-sni',
      summary:
        'A publicly rooted, in-date chain whose only dNSName covers a different name than the SNI ' +
        'that was sent - the certificate an appliance keying off the address rather than the SNI emits.',
      capturedAt: CAPTURED_AT.toISOString(),
      host: HOST,
      publicAnchor: anchor,
      direct: capture(await publicChain({ dnsNames: ['other.example.net'] })),
    },
  ];
}

for (const file of await files()) {
  const path = recordedChainPath(file.condition);
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, 'utf8');
  console.log(`recorded ${path}`);
}
