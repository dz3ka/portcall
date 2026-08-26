import { describe, expect, it } from 'vitest';
import { classifyAuthScheme } from '../src/probes/proxy/auth.ts';
import type { AuthScheme } from '../src/net/types.ts';

interface Case {
  readonly label: string;
  readonly headerValue: string | null;
  readonly scheme: AuthScheme;
}

const CASES: readonly Case[] = [
  { label: 'no header at all', headerValue: null, scheme: 'none' },
  { label: 'an empty header value', headerValue: '', scheme: 'none' },
  { label: 'a whitespace-only header value', headerValue: '   ', scheme: 'none' },
  { label: 'Basic with a realm', headerValue: 'Basic realm="corp"', scheme: 'Basic' },
  { label: 'bare Basic', headerValue: 'Basic', scheme: 'Basic' },
  { label: 'lowercase basic', headerValue: 'basic realm="corp"', scheme: 'Basic' },
  { label: 'bare NTLM', headerValue: 'NTLM', scheme: 'NTLM' },
  { label: 'NTLM with a base64 token', headerValue: 'NTLM TlRMTVNTUAABAAAA', scheme: 'NTLM' },
  { label: 'bare Negotiate', headerValue: 'Negotiate', scheme: 'Negotiate' },
  { label: 'Negotiate with a token', headerValue: 'Negotiate YIIB...', scheme: 'Negotiate' },
  { label: 'Negotiate listed first wins over NTLM', headerValue: 'Negotiate, NTLM', scheme: 'Negotiate' },
  { label: 'NTLM listed first wins over Basic', headerValue: 'NTLM, Basic realm="corp"', scheme: 'NTLM' },
  { label: 'multiple WWW-Authenticate challenges, comma-joined, earliest wins', headerValue: 'Basic realm="corp", NTLM', scheme: 'Basic' },
  { label: 'an unrecognized scheme (Digest is not in the closed union)', headerValue: 'Digest realm="corp"', scheme: 'unknown' },
  { label: 'garbage text', headerValue: 'not a real challenge', scheme: 'unknown' },
];

describe('classifyAuthScheme', () => {
  it.each(CASES)('$label -> $scheme', ({ headerValue, scheme }) => {
    expect(classifyAuthScheme(headerValue)).toBe(scheme);
  });

  it('reaches every AuthScheme member across the table', () => {
    const produced = new Set<AuthScheme>(CASES.map((c) => c.scheme));
    const expected: readonly AuthScheme[] = ['Basic', 'NTLM', 'Negotiate', 'none', 'unknown'];
    expect([...produced].sort()).toEqual([...expected].sort());
  });

  it('never returns anything beyond the scheme name (no realm/token leakage)', () => {
    const scheme = classifyAuthScheme('Basic realm="do-not-leak-this-realm-name", NTLM TlRMTVNTUAABAAAA');
    expect(scheme).toBe('Basic');
    // Structural guarantee too: AuthScheme is a string-literal union, so a
    // realm or token could only ever leak by being returned verbatim - it
    // is not, by inspection of classifyAuthScheme's body (no substring of
    // the header ever reaches the return value).
    expect(typeof scheme).toBe('string');
    expect(['Basic', 'NTLM', 'Negotiate', 'none', 'unknown']).toContain(scheme);
  });
});
