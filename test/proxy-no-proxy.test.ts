import { describe, expect, it } from 'vitest';
import { validateNoProxy } from '../src/probes/proxy/no-proxy.ts';
import type { NoProxyEntry, NoProxyEntryIssue, NoProxyTarget } from '../src/probes/proxy/no-proxy.ts';

/**
 * Targets, not bare hostnames: a `NO_PROXY` entry may carry a port, and an
 * entry that carries one bypasses the proxy for that port only. Written as
 * `host:port` strings in the expectations below purely so the table stays
 * readable.
 */
const PROFILE_TARGETS: readonly NoProxyTarget[] = [
  { host: 'api.example.com', port: 443 },
  { host: 'registry.npmjs.org', port: 443 },
  { host: 'example.com', port: 80 },
  { host: 'sub.internal.example.com', port: 8443 },
];

const ALL_TARGETS = ['api.example.com:443', 'registry.npmjs.org:443', 'example.com:80', 'sub.internal.example.com:8443'];

function asStrings(targets: readonly NoProxyTarget[]): string[] {
  return targets.map((target) => `${target.host}:${String(target.port)}`);
}

describe('validateNoProxy: empty input', () => {
  it('an empty/unset variable has no entries', () => {
    expect(validateNoProxy('', PROFILE_TARGETS)).toEqual([]);
    expect(validateNoProxy('   ', PROFILE_TARGETS)).toEqual([]);
  });

  it('an empty entry between commas is reported as "empty"', () => {
    const entries = validateNoProxy('api.example.com,,registry.npmjs.org', PROFILE_TARGETS);
    expect(entries).toHaveLength(3);
    expect(entries[1]).toEqual({ raw: '', issue: 'empty', matchedTargets: [] });
  });
});

interface Case {
  readonly label: string;
  readonly entry: string;
  readonly issue: NoProxyEntryIssue;
  /** `host:port`, as `asStrings` renders them. */
  readonly matches?: readonly string[];
}

const CASES: readonly Case[] = [
  // ok: exact host
  { label: 'exact host match', entry: 'api.example.com', issue: 'ok', matches: ['api.example.com:443'] },
  { label: 'exact host, no match', entry: 'other.example.com', issue: 'ok', matches: [] },
  { label: 'exact host is case-insensitive', entry: 'API.EXAMPLE.COM', issue: 'ok', matches: ['api.example.com:443'] },
  // ok: host:port - the port is part of the match, not decoration
  { label: 'a port-qualified entry matches the endpoint on that port', entry: 'api.example.com:443', issue: 'ok', matches: ['api.example.com:443'] },
  { label: 'a port-qualified entry does not match the same host on another port', entry: 'api.example.com:8080', issue: 'ok', matches: [] },
  { label: 'a port-qualified suffix entry matches only on that port', entry: '.example.com:80', issue: 'ok', matches: ['example.com:80'] },
  // ok: leading-dot domain suffix
  {
    label: 'leading-dot matches the bare domain and subdomains',
    entry: '.example.com',
    issue: 'ok',
    matches: ['api.example.com:443', 'example.com:80', 'sub.internal.example.com:8443'],
  },
  // ok: leading wildcard
  {
    label: 'leading "*." wildcard behaves like a leading dot',
    entry: '*.example.com',
    issue: 'ok',
    matches: ['api.example.com:443', 'example.com:80', 'sub.internal.example.com:8443'],
  },
  { label: 'bare "*" matches every profile target', entry: '*', issue: 'ok', matches: ALL_TARGETS },
  // ok: localhost / single label
  { label: 'a plain single-label host is valid', entry: 'localhost', issue: 'ok', matches: [] },
  // ok: CIDR (syntactically valid, never matches at this pure layer)
  { label: 'IPv4 CIDR validates but matches nothing (hostnames, not IPs, at this layer)', entry: '10.0.0.0/8', issue: 'ok', matches: [] },
  { label: 'IPv4 CIDR /32', entry: '192.168.1.1/32', issue: 'ok', matches: [] },
  // contains-scheme
  { label: 'a scheme prefix is invalid', entry: 'http://example.com', issue: 'contains-scheme' },
  { label: 'https scheme prefix is invalid', entry: 'https://example.com', issue: 'contains-scheme' },
  // wildcard-not-leading
  { label: 'a wildcard mid-string is invalid', entry: 'sub*.example.com', issue: 'wildcard-not-leading' },
  { label: 'a wildcard at the end is invalid', entry: 'example.com*', issue: 'wildcard-not-leading' },
  // contains-port-with-wildcard
  { label: 'a leading wildcard combined with a port is ambiguous', entry: '*.example.com:8080', issue: 'contains-port-with-wildcard' },
  { label: 'a bare wildcard with a port is ambiguous', entry: '*:8080', issue: 'contains-port-with-wildcard' },
  // invalid-hostname
  { label: 'an empty label is invalid', entry: '..example.com', issue: 'invalid-hostname' },
  { label: 'a space is not a valid hostname character', entry: 'exa mple.com', issue: 'invalid-hostname' },
  { label: 'an "@" is not a valid hostname character', entry: 'user@example.com', issue: 'invalid-hostname' },
  { label: 'a lone dot is not a valid hostname', entry: '.', issue: 'invalid-hostname' },
];
describe('validateNoProxy: entry classification', () => {
  it.each(CASES)('$label ($entry)', ({ entry, issue, matches }) => {
    const [result] = validateNoProxy(entry, PROFILE_TARGETS);
    expect(result).toBeDefined();
    expect((result as NoProxyEntry).issue).toBe(issue);
    if (matches !== undefined) {
      expect(asStrings((result as NoProxyEntry).matchedTargets).sort()).toEqual([...matches].sort());
    }
  });

  it('reaches every NoProxyEntryIssue member across the table', () => {
    const produced = new Set<NoProxyEntryIssue>(CASES.map((c) => c.issue));
    produced.add('empty'); // covered by its own describe block above
    const expected: readonly NoProxyEntryIssue[] = ['ok', 'empty', 'contains-scheme', 'contains-port-with-wildcard', 'invalid-hostname', 'wildcard-not-leading'];
    expect([...produced].sort()).toEqual([...expected].sort());
  });
});

describe('validateNoProxy: comma-separated list end to end', () => {
  it('a realistic NO_PROXY value classifies every entry independently', () => {
    const raw = '.example.com,10.0.0.0/8,localhost,*.internal';
    const entries = validateNoProxy(raw, PROFILE_TARGETS);
    expect(entries.map((e) => e.raw)).toEqual(['.example.com', '10.0.0.0/8', 'localhost', '*.internal']);
    expect(entries.map((e) => e.issue)).toEqual(['ok', 'ok', 'ok', 'ok']);
    expect(asStrings(entries[0]?.matchedTargets ?? []).sort()).toEqual(
      ['api.example.com:443', 'example.com:80', 'sub.internal.example.com:8443'].sort(),
    );
  });

  it('surrounding whitespace around entries is trimmed', () => {
    const entries = validateNoProxy(' api.example.com , localhost ', PROFILE_TARGETS);
    expect(entries.map((e) => e.raw)).toEqual(['api.example.com', 'localhost']);
  });
});

/**
 * The port half of the match rule, on a host declared twice. This is the
 * regression for a `NO_PROXY` entry that named one port and bypassed every
 * port: the endpoint on the un-named port must still route through the proxy,
 * because that is what curl and Node do with the same variable.
 */
describe('validateNoProxy: a port-qualified entry binds to that port only', () => {
  const SAME_HOST: readonly NoProxyTarget[] = [
    { host: 'api.example.com', port: 443 },
    { host: 'api.example.com', port: 8080 },
  ];

  it('bypasses only the endpoint on the named port', () => {
    const [entry] = validateNoProxy('api.example.com:8080', SAME_HOST);
    expect(asStrings((entry as NoProxyEntry).matchedTargets)).toEqual(['api.example.com:8080']);
  });

  it('bypasses every port when the entry names none', () => {
    const [entry] = validateNoProxy('api.example.com', SAME_HOST);
    expect(asStrings((entry as NoProxyEntry).matchedTargets)).toEqual(['api.example.com:443', 'api.example.com:8080']);
  });
});
