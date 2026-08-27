import { describe, expect, it } from 'vitest';
import { X509Certificate } from '@peculiar/x509';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import { canonicalDn, classifyRoot, publicRootIndex } from '../src/probes/tls/public-roots.ts';
import type { RootClass, RootReason, RootVerdict } from '../src/probes/tls/public-roots.ts';
import { derOfPem, subjectOfPem, syntheticChain } from './helpers/synthetic-chain.ts';

/**
 * Public-root classification (M3, ADR-0002 D3).
 *
 * The verdict this file covers is the most alarming one portcall emits, so the
 * tests run against the *real* bundle - `PUBLIC_ROOT_CA_PEMS`, the runtime's
 * own Mozilla list - and not a stand-in. That keeps the classification honest
 * about the list it will actually be given at runtime, but it is a statement
 * about *this* process's bundle only: Node and Bun ship different Mozilla
 * snapshots and always have (ADR-0031), so nothing here generalises to another
 * runtime by itself.
 *
 * What generalises is measured next door. `test/net-root-bundle.test.ts` runs
 * the same `publicRootIndex`/`classifyRoot` under Node and under Bun over a
 * *fixed* reference root set built from the committed fixtures, and requires
 * identical verdicts - so the code is proven runtime-agnostic with the bundle
 * held still. It separately requires that the roots those fixtures anchor in
 * ship in both runtimes' own bundles, which is the one bundle difference that
 * could flip a verdict for a customer.
 */

const ROOTS = publicRootIndex(PUBLIC_ROOT_CA_PEMS);

/** Three roots from across the bundle, so the test is not an accident of ordering. */
function samplePems(): string[] {
  const pems = [...PUBLIC_ROOT_CA_PEMS];
  const first = pems[0];
  const middle = pems[Math.floor(pems.length / 2)];
  const last = pems[pems.length - 1];
  if (first === undefined || middle === undefined || last === undefined) throw new Error('empty root bundle');
  return [first, middle, last];
}

function parse(chain: readonly Uint8Array[]): X509Certificate[] {
  return chain.map((der) => new X509Certificate(der));
}

interface Expectation {
  class: RootClass;
  reason: RootReason;
}

function verdictOf(chain: readonly Uint8Array[]): Expectation {
  const verdict = classifyRoot(parse(chain), ROOTS);
  return { class: verdict.class, reason: verdict.reason };
}

/** The whole verdict, for the tests that are about *where* on the chain the answer came from. */
function fullVerdict(chain: readonly Uint8Array[]): RootVerdict {
  return classifyRoot(parse(chain), ROOTS);
}

describe('public root index', () => {
  it('indexes the whole runtime bundle', () => {
    expect(ROOTS.size).toBe(PUBLIC_ROOT_CA_PEMS.length);
    expect(ROOTS.size).toBeGreaterThan(50);
  });

  it('recognises every root in the bundle by its bytes', () => {
    for (const pem of PUBLIC_ROOT_CA_PEMS) {
      expect(ROOTS.hasCertificate(derOfPem(pem))).toBe(true);
    }
  });

  it('does not recognise a certificate that is not in the bundle', async () => {
    const [der] = await syntheticChain([{ subject: 'CN=Acme Corp Internal Root, O=Acme Corp' }]);
    expect(der).toBeDefined();
    expect(ROOTS.hasCertificate(der as Uint8Array)).toBe(false);
  });
});

describe('distinguished name canonicalisation', () => {
  it('ignores case and internal whitespace, both of which a DN comparison must not depend on', () => {
    const plain = new X509Certificate(
      // Same DN, three spellings; only the *encoding* differs.
      PUBLIC_ROOT_CA_PEMS[0] ?? '',
    );
    expect(canonicalDn(plain.subjectName)).toBe(canonicalDn(plain.subjectName));
    expect(ROOTS.hasSubject(canonicalDn(plain.subjectName))).toBe(true);
  });

  it('matches a DN written with different case and spacing to the same bundled root', async () => {
    const subject = subjectOfPem(samplePems()[0] ?? '');
    const [der] = await syntheticChain([{ subject: subject.toUpperCase(), issuer: 'CN=Somebody Else' }]);
    if (der === undefined) throw new Error('no certificate generated');
    const cert = new X509Certificate(der);
    expect(ROOTS.hasSubject(canonicalDn(cert.subjectName))).toBe(true);
  });
});

describe('root classification', () => {
  it('calls a chain public when a bundled root is presented in it', async () => {
    for (const pem of samplePems()) {
      const rootDer = derOfPem(pem);
      const [leaf] = await syntheticChain([
        { subject: 'CN=api.example.com', issuer: subjectOfPem(pem), dnsNames: ['api.example.com'] },
      ]);
      expect(verdictOf([leaf as Uint8Array, rootDer])).toEqual({
        class: 'public',
        reason: 'bundled-root-on-path',
      });
    }
  });

  it('calls a bare bundled root public, so the match is on bytes and not on position', () => {
    const pem = samplePems()[1] ?? '';
    expect(verdictOf([derOfPem(pem)])).toEqual({ class: 'public', reason: 'bundled-root-on-path' });
  });

  it('calls a self-signed anchor the runtime does not ship private', async () => {
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Internal Root, O=Acme Corp' },
    ]);
    expect(verdictOf(chain)).toEqual({ class: 'private', reason: 'self-signed-anchor-not-bundled' });
  });

  it('calls a chain private when nothing in the bundle could have issued its topmost certificate', async () => {
    // The anchor was not presented, but its *name* is not the subject of any
    // public root either - so no public root can be at the top, whatever the
    // signatures say. Absence of a name match is conclusive; presence is not.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Issuing CA', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp' },
    ]);
    expect(verdictOf(chain)).toEqual({ class: 'private', reason: 'issuer-matches-no-bundled-root' });
  });

  it('refuses to call a chain public on the strength of an issuer name alone', async () => {
    // Anyone can write a public root's DN into their issuer field. Proving it
    // wrong needs a signature check, which ADR-0021 puts out of scope - so the
    // honest verdict is that we do not know, not that it is public.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Issuing CA', issuer: subjectOfPem(samplePems()[2] ?? '') },
    ]);
    expect(verdictOf(chain)).toEqual({ class: 'indeterminate', reason: 'anchor-not-presented' });
  });
});

/**
 * The issuance path (M3, WP8).
 *
 * A chain is not a bag of certificates: only the ones the leaf actually points
 * at, issuer DN to subject DN, are part of it. Everything else in the array is
 * something the peer chose to send, and a verdict that reads it is a verdict an
 * attacker can write.
 */
describe('issuance path', () => {
  it('ignores a bundled root the leaf does not lead to, so padding cannot buy a public verdict', async () => {
    // A private chain with a public root stapled on the end. Nothing in the
    // chain names that root as its issuer, so it is not part of this chain.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Internal Root, O=Acme Corp' },
    ]);
    const verdict = fullVerdict([...chain, derOfPem(samplePems()[0] ?? '')]);
    expect(verdict.class).toBe('private');
    expect(verdict.reason).toBe('self-signed-anchor-not-bundled');
    expect(verdict.matchedIndex).toBeNull();
    expect(verdict.path).toEqual([0, 1]);
  });

  it('honours a bundled root that is on the path but not last, as a cross-signed chain presents it', async () => {
    // The shape Let's Encrypt served for years: the bundled root is the third
    // certificate and a legacy root nobody ships any more follows it.
    const pem = samplePems()[1] ?? '';
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Issuing CA', issuer: subjectOfPem(pem) },
    ]);
    const legacy = await syntheticChain([{ subject: 'CN=Legacy Root 2005' }]);
    const verdict = fullVerdict([...chain, derOfPem(pem), ...legacy]);
    expect(verdict.class).toBe('public');
    expect(verdict.reason).toBe('bundled-root-on-path');
    expect(verdict.matchedIndex).toBe(2);
    expect(verdict.path).toEqual([0, 1, 2]);
  });

  it('reads the anchor at the end of the path, not at the end of the array', async () => {
    // The topmost certificate is off-path padding that is self-signed and not
    // bundled; reading it as the anchor would report `private` for a chain
    // whose real terminus only failed to present its issuer.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Issuing CA', issuer: subjectOfPem(samplePems()[2] ?? '') },
      { subject: 'CN=Unrelated Self-Signed Root' },
    ]);
    const verdict = fullVerdict(chain);
    expect(verdict.path).toEqual([0, 1]);
    expect(verdict.class).toBe('indeterminate');
    expect(verdict.reason).toBe('anchor-not-presented');
  });

  it('ends the path at a self-signed certificate rather than looping on its own subject', () => {
    const verdict = fullVerdict([derOfPem(samplePems()[1] ?? '')]);
    expect(verdict.path).toEqual([0]);
    expect(verdict.matchedIndex).toBe(0);
  });

  it('takes the first unvisited certificate when two presented certificates share a subject', async () => {
    // A cross-signed CA sent twice, once under each of its issuers. Both are on
    // a legitimate path, so following either reaches the same bundled root.
    const pem = samplePems()[0] ?? '';
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Corp Issuing CA', issuer: subjectOfPem(pem) },
      { subject: 'CN=Acme Corp Issuing CA', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp' },
    ]);
    const verdict = fullVerdict([...chain, derOfPem(pem)]);
    expect(verdict.path).toEqual([0, 1, 3]);
    expect(verdict.class).toBe('public');
    expect(verdict.matchedIndex).toBe(3);
  });

  it('terminates on a chain whose issuer names form a cycle', async () => {
    // Two CAs that name each other. Nothing stops a peer sending this, and the
    // walk has to end on it without visiting a certificate twice.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme CA A', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme CA A', issuer: 'CN=Acme CA B' },
      { subject: 'CN=Acme CA B', issuer: 'CN=Acme CA A' },
    ]);
    const verdict = fullVerdict(chain);
    expect(verdict.path).toEqual([0, 1, 2]);
    expect(verdict.class).toBe('private');
    expect(verdict.reason).toBe('issuer-matches-no-bundled-root');
  });
});
