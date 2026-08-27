import { beforeAll, describe, expect, it } from 'vitest';
import { assertRemediable } from '../src/model/finding.ts';
import type { Finding } from '../src/model/finding.ts';
import type { Profile } from '../src/profiles/schema.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../src/net/root-bundle.ts';
import { EXPIRY_WARNING_DAYS, compareChains, evaluateChain } from '../src/probes/tls/evaluate.ts';
import type { CapturedChain, ChainEvaluationOptions } from '../src/probes/tls/evaluate.ts';
import { certificateIndex } from '../src/probes/shared/root-index.ts';
import { derOfPem, subjectOfPem, syntheticChain } from './helpers/synthetic-chain.ts';

/**
 * TLS chain evaluation (M3, WP3). Pure: raw DER in, findings out, no socket
 * and no clock - `now` is injected so the expiry rows are ordinary table tests
 * rather than something that starts failing on a Tuesday.
 */

const NOW = new Date('2026-08-26T00:00:00Z');
const DAY_MS = 24 * 60 * 60 * 1000;

function daysFromNow(days: number): Date {
  return new Date(NOW.getTime() + days * DAY_MS);
}

const OPTIONS: ChainEvaluationOptions = { roots: certificateIndex(PUBLIC_ROOT_CA_PEMS), now: NOW };
const TARGET = { host: 'api.example.com', required: true };
const STRICT: Pick<Profile, 'tls'> = { tls: { min_version: '1.2', interception_tolerated: false } };
const TOLERANT: Pick<Profile, 'tls'> = { tls: { min_version: '1.2', interception_tolerated: true } };

const PUBLIC_ROOT_PEM = PUBLIC_ROOT_CA_PEMS[0] ?? '';

function capture(chainDer: readonly Uint8Array[], overrides: Partial<CapturedChain> = {}): CapturedChain {
  return {
    chainDer,
    negotiatedProtocol: 'TLSv1.3',
    negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
    requestedSni: 'api.example.com',
    via: 'direct',
    ...overrides,
  };
}

function ids(findings: readonly Finding[]): string[] {
  return findings.map((finding) => finding.id);
}

function only(findings: readonly Finding[], id: string): Finding {
  const found = findings.find((finding) => finding.id === id);
  if (found === undefined) throw new Error(`expected a ${id} finding, got: ${ids(findings).join(', ')}`);
  return found;
}

interface LeafShape {
  notBefore?: Date;
  notAfter?: Date;
  dnsNames?: readonly string[];
}

/** A leaf under a *public* root, with the root presented, so only the dimension under test varies. */
async function publicChain(leaf: LeafShape = {}, withSan = true): Promise<Uint8Array[]> {
  const chain = await syntheticChain([
    {
      subject: 'CN=api.example.com',
      issuer: subjectOfPem(PUBLIC_ROOT_PEM),
      ...(withSan ? { dnsNames: leaf.dnsNames ?? ['api.example.com'] } : {}),
      ...(leaf.notBefore === undefined ? {} : { notBefore: leaf.notBefore }),
      ...(leaf.notAfter === undefined ? {} : { notAfter: leaf.notAfter }),
    },
  ]);
  return [...chain, derOfPem(PUBLIC_ROOT_PEM)];
}

let PUBLIC_CHAIN: Uint8Array[];
let PRIVATE_CHAIN: Uint8Array[];
let PADDED_PRIVATE_CHAIN: Uint8Array[];

beforeAll(async () => {
  PUBLIC_CHAIN = await publicChain();
  PRIVATE_CHAIN = await syntheticChain([
    { subject: 'CN=api.example.com', issuer: 'CN=Acme Corp Internal Root, O=Acme Corp', dnsNames: ['api.example.com'] },
    { subject: 'CN=Acme Corp Internal Root, O=Acme Corp' },
  ]);
  PADDED_PRIVATE_CHAIN = [...PRIVATE_CHAIN, derOfPem(PUBLIC_ROOT_PEM)];
});

describe('root verdict', () => {
  it('passes a chain anchored in a root the runtime ships', () => {
    const findings = evaluateChain(capture(PUBLIC_CHAIN), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).toContain('tls.public-root');
    expect(only(findings, 'tls.public-root').severity).toBe('ok');
    expect(findings.filter((finding) => finding.severity !== 'ok')).toEqual([]);
  });

  it('names the matched public root in the clear, because it is public knowledge', () => {
    const finding = only(evaluateChain(capture(PUBLIC_CHAIN), TARGET, STRICT, OPTIONS), 'tls.public-root');
    const root = finding.evidence.find((evidence) => evidence.label === 'root');
    expect(root?.kind).toBe('public');
    expect(root?.value).toBe(subjectOfPem(PUBLIC_ROOT_PEM));
  });

  it('blocks on a private root when the profile does not tolerate interception', () => {
    const finding = only(evaluateChain(capture(PRIVATE_CHAIN), TARGET, STRICT, OPTIONS), 'tls.private-root');
    expect(finding.severity).toBe('blocker');
    expect(finding.remediation).toBeTruthy();
  });

  it('degrades rather than blocks when the profile tolerates interception', () => {
    const finding = only(evaluateChain(capture(PRIVATE_CHAIN), TARGET, TOLERANT, OPTIONS), 'tls.private-root');
    expect(finding.severity).toBe('degraded');
  });

  it('caps the blocker to degraded for an endpoint the profile does not require', () => {
    const findings = evaluateChain(
      capture(PRIVATE_CHAIN),
      { host: 'api.example.com', required: false },
      STRICT,
      OPTIONS,
    );
    expect(only(findings, 'tls.private-root').severity).toBe('degraded');
  });

  it('carries the private root name as a `dn`, never as free text', () => {
    const finding = only(evaluateChain(capture(PRIVATE_CHAIN), TARGET, STRICT, OPTIONS), 'tls.private-root');
    const named = finding.evidence.filter((evidence) => evidence.value.includes('Acme Corp'));
    expect(named.length).toBeGreaterThan(0);
    for (const evidence of named) expect(evidence.kind).toBe('dn');
  });

  it('blocks on a private chain even when a bundled public root is appended as padding', () => {
    // Anyone can staple a public root onto a private chain. The leaf does not
    // lead to it, so it is not part of the chain and cannot suppress the
    // blocker (WP8).
    const findings = evaluateChain(capture(PADDED_PRIVATE_CHAIN), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).not.toContain('tls.public-root');
    expect(only(findings, 'tls.private-root').severity).toBe('blocker');
  });

  it('reports the anchor at the end of the issuance path, not the padding after it', () => {
    const finding = only(evaluateChain(capture(PADDED_PRIVATE_CHAIN), TARGET, STRICT, OPTIONS), 'tls.private-root');
    const subject = finding.evidence.find((evidence) => evidence.label === 'subject');
    expect(subject?.value).toContain('Acme Corp Internal Root');
    expect(subject?.value).not.toContain(subjectOfPem(PUBLIC_ROOT_PEM));
  });

  it('counts the certificates on the issuance path alongside the ones presented', () => {
    const finding = only(evaluateChain(capture(PADDED_PRIVATE_CHAIN), TARGET, STRICT, OPTIONS), 'tls.private-root');
    const valueOf = (label: string): string | undefined =>
      finding.evidence.find((evidence) => evidence.label === label)?.value;
    expect(valueOf('certificates presented')).toBe('3');
    expect(valueOf('certificates on issuance path')).toBe('2');
  });

  it('says it does not know when the anchor was never presented', async () => {
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Issuing CA', issuer: subjectOfPem(PUBLIC_ROOT_PEM) },
    ]);
    const finding = only(evaluateChain(capture(chain), TARGET, STRICT, OPTIONS), 'tls.root-indeterminate');
    expect(finding.severity).toBe('unknown');
  });
});

describe('negotiated protocol', () => {
  it('passes a protocol at or above the profile minimum', () => {
    const finding = only(evaluateChain(capture(PUBLIC_CHAIN), TARGET, STRICT, OPTIONS), 'tls.protocol');
    expect(finding.severity).toBe('ok');
    expect(finding.evidence.map((evidence) => evidence.value)).toContain('TLSv1.3');
  });

  it('blocks a protocol below the profile minimum', () => {
    const findings = evaluateChain(capture(PUBLIC_CHAIN, { negotiatedProtocol: 'TLSv1' }), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.protocol-below-minimum').severity).toBe('blocker');
  });

  it('accepts exactly the profile minimum', () => {
    const findings = evaluateChain(capture(PUBLIC_CHAIN, { negotiatedProtocol: 'TLSv1.2' }), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).toContain('tls.protocol');
  });

  it.each([null, 'TLSv9.9 (corp-inspection-gw)'])(
    'reports an unusable protocol name (%s) as unknown and never repeats it',
    (protocol) => {
      const findings = evaluateChain(capture(PUBLIC_CHAIN, { negotiatedProtocol: protocol }), TARGET, STRICT, OPTIONS);
      expect(only(findings, 'tls.protocol-unknown').severity).toBe('unknown');
      expect(JSON.stringify(findings)).not.toContain('corp-inspection-gw');
    },
  );
});

describe('validity window', () => {
  it('blocks on a certificate that has already expired', async () => {
    const findings = evaluateChain(capture(await publicChain({ notAfter: daysFromNow(-1) })), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.chain-expired').severity).toBe('blocker');
    expect(ids(findings)).not.toContain('tls.chain-expiring-soon');
  });

  it('warns inside the expiry window', async () => {
    const chain = await publicChain({ notAfter: daysFromNow(EXPIRY_WARNING_DAYS - 1) });
    const findings = evaluateChain(capture(chain), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.chain-expiring-soon').severity).toBe('degraded');
  });

  it('says nothing about a certificate beyond the expiry window', async () => {
    const chain = await publicChain({ notAfter: daysFromNow(EXPIRY_WARNING_DAYS + 1) });
    const findings = evaluateChain(capture(chain), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).not.toContain('tls.chain-expiring-soon');
    expect(ids(findings)).not.toContain('tls.chain-expired');
  });

  it('reports a certificate that is not valid yet separately: that is a clock, not a renewal', async () => {
    const chain = await publicChain({ notBefore: daysFromNow(2), notAfter: daysFromNow(400) });
    const findings = evaluateChain(capture(chain), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.chain-not-yet-valid').severity).toBe('blocker');
  });
});

describe('name matching', () => {
  it('accepts an exact dNSName match', () => {
    expect(ids(evaluateChain(capture(PUBLIC_CHAIN), TARGET, STRICT, OPTIONS))).not.toContain('tls.sni-mismatch');
  });

  it('accepts a wildcard covering one label', async () => {
    const chain = await publicChain({ dnsNames: ['*.example.com'] });
    expect(ids(evaluateChain(capture(chain), TARGET, STRICT, OPTIONS))).not.toContain('tls.sni-mismatch');
  });

  it('does not let a wildcard span a dot', async () => {
    const chain = await publicChain({ dnsNames: ['*.example.com'] });
    const findings = evaluateChain(capture(chain, { requestedSni: 'a.b.example.com' }), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.sni-mismatch').severity).toBe('blocker');
  });

  it('does not let a wildcard match the bare parent domain', async () => {
    const chain = await publicChain({ dnsNames: ['*.example.com'] });
    const findings = evaluateChain(capture(chain, { requestedSni: 'example.com' }), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).toContain('tls.sni-mismatch');
  });

  it('blocks when no SAN entry covers the name that was asked for', async () => {
    const chain = await publicChain({ dnsNames: ['other.example.net'] });
    const finding = only(evaluateChain(capture(chain), TARGET, STRICT, OPTIONS), 'tls.sni-mismatch');
    expect(finding.severity).toBe('blocker');
    const hostnames = finding.evidence.filter((evidence) => evidence.kind === 'hostname');
    expect(hostnames.map((evidence) => evidence.value)).toContain('other.example.net');
  });

  it('reports a leaf with no SAN extension as its own finding', async () => {
    const chain = await publicChain({}, false);
    const findings = evaluateChain(capture(chain), TARGET, STRICT, OPTIONS);
    expect(only(findings, 'tls.leaf-no-san').severity).toBe('blocker');
    expect(ids(findings)).not.toContain('tls.sni-mismatch');
  });

  it('judges no name at all when the target was a literal address', () => {
    const findings = evaluateChain(capture(PUBLIC_CHAIN, { requestedSni: '' }), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).not.toContain('tls.sni-mismatch');
    expect(ids(findings)).not.toContain('tls.leaf-no-san');
  });
});

describe('chains that cannot be read', () => {
  it('reports an empty chain as unknown rather than guessing', () => {
    const findings = evaluateChain(capture([]), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).toEqual(['tls.chain-empty']);
    expect(only(findings, 'tls.chain-empty').severity).toBe('unknown');
  });

  it('reports unparseable DER as unknown rather than throwing', () => {
    const findings = evaluateChain(capture([new Uint8Array([0x30, 0x01, 0x00])]), TARGET, STRICT, OPTIONS);
    expect(ids(findings)).toEqual(['tls.chain-unparseable']);
  });
});

describe('direct versus proxied chain', () => {
  it('reports interception when the proxy presents a different leaf', () => {
    const findings = compareChains(capture(PUBLIC_CHAIN), capture(PRIVATE_CHAIN, { via: 'proxy' }), TARGET);
    expect(only(findings, 'tls.intercepted-via-proxy').remediation).toBeTruthy();
  });

  it('reports consistency when both paths present the same leaf', () => {
    const findings = compareChains(capture(PUBLIC_CHAIN), capture(PUBLIC_CHAIN, { via: 'proxy' }), TARGET);
    expect(ids(findings)).toEqual(['tls.chain-consistent']);
    expect(only(findings, 'tls.chain-consistent').severity).toBe('ok');
  });

  // The interception severity is pinned here rather than left to a doc
  // comment, because threading a profile through this comparison breaks two
  // ways. A proxied chain that was re-signed already blocks on
  // `tls.private-root` for the same host, asserted alongside below, so
  // escalating here would count one broken thing twice; and a proxied chain
  // that differs while staying publicly rooted - a CDN POP or a load balancer
  // rotating a certificate - is a normal network, where a blocker is false.
  it.each([
    ['a profile that refuses interception, on a required endpoint', STRICT, true, 'blocker'],
    ['a profile that refuses interception, on an optional endpoint', STRICT, false, 'degraded'],
    ['a profile that tolerates interception, on a required endpoint', TOLERANT, true, 'degraded'],
    ['a profile that tolerates interception, on an optional endpoint', TOLERANT, false, 'degraded'],
  ] as const)('holds the interception finding at degraded under %s', (_label, profile, required, trustVerdict) => {
    const target = { host: TARGET.host, required };
    const proxied = capture(PRIVATE_CHAIN, { via: 'proxy' });

    const compared = compareChains(capture(PUBLIC_CHAIN), proxied, target);
    expect(only(compared, 'tls.intercepted-via-proxy').severity).toBe('degraded');
    expect(only(evaluateChain(proxied, target, profile, OPTIONS), 'tls.private-root').severity).toBe(trustVerdict);
  });

  it('holds it at degraded when the two chains differ but both are publicly rooted', async () => {
    const rotated = await publicChain();
    const findings = compareChains(capture(PUBLIC_CHAIN), capture(rotated, { via: 'proxy' }), TARGET);
    expect(only(findings, 'tls.intercepted-via-proxy').severity).toBe('degraded');
  });

  it.each([
    ['no direct chain', false, true],
    ['no proxied chain', true, false],
    ['neither', false, false],
  ] as const)('concludes nothing from %s', (_label, hasDirect, hasProxied) => {
    const findings = compareChains(
      hasDirect ? capture(PUBLIC_CHAIN) : null,
      hasProxied ? capture(PRIVATE_CHAIN, { via: 'proxy' }) : null,
      TARGET,
    );
    expect(findings).toEqual([]);
  });
});

describe('the remediation rule', () => {
  it('holds for every finding these tests can produce', async () => {
    const chains: Uint8Array[][] = [
      PUBLIC_CHAIN,
      PRIVATE_CHAIN,
      [],
      await publicChain({ notAfter: daysFromNow(-1) }),
      await publicChain({ notAfter: daysFromNow(1) }),
      await publicChain({ notBefore: daysFromNow(2), notAfter: daysFromNow(400) }),
      await publicChain({ dnsNames: ['other.example.net'] }),
      await publicChain({}, false),
    ];
    const findings = chains.flatMap((chain) =>
      [STRICT, TOLERANT].flatMap((profile) =>
        [null, 'TLSv1', 'TLSv1.3'].flatMap((protocol) =>
          evaluateChain(capture(chain, { negotiatedProtocol: protocol }), TARGET, profile, OPTIONS),
        ),
      ),
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) expect(() => assertRemediable(finding)).not.toThrow();
  });
});

describe('root verdict on the issuance path', () => {
  it('names the indeterminate anchor from the path terminus and counts the path', async () => {
    // The last array element is off-path padding; the finding must describe the
    // certificate the leaf actually leads to.
    const chain = await syntheticChain([
      { subject: 'CN=api.example.com', issuer: 'CN=Acme Issuing CA', dnsNames: ['api.example.com'] },
      { subject: 'CN=Acme Issuing CA', issuer: subjectOfPem(PUBLIC_ROOT_PEM) },
      { subject: 'CN=Unrelated Self-Signed Root' },
    ]);
    const finding = only(evaluateChain(capture(chain), TARGET, STRICT, OPTIONS), 'tls.root-indeterminate');
    const named = finding.evidence.find((evidence) => evidence.label === 'names as issuer');
    expect(named?.value).toBe(subjectOfPem(PUBLIC_ROOT_PEM));
    const onPath = finding.evidence.find((evidence) => evidence.label === 'certificates on issuance path');
    expect(onPath?.value).toBe('2');
  });
});
