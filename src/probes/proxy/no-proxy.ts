/**
 * `NO_PROXY`/`no_proxy` syntax validation (M2).
 *
 * Pure: no environment access here — the caller reads the env var and hands
 * its raw text in. This module classifies each comma-separated entry against
 * a closed issue union and reports which of the profile's declared endpoints
 * it would bypass the proxy for, following the conventions curl/most HTTP
 * clients use (leading-dot domain suffix, leading-`*` wildcard, exact host).
 *
 * Entries match `(host, port)` targets, not bare hostnames, because
 * `NO_PROXY` entries may carry a port and curl, Node and python-requests all
 * treat that port as part of the match: `api.example.com:8080` bypasses the
 * proxy for port 8080 and for nothing else. Matching on the hostname alone
 * would report a bypass — an `ok` finding, and a skipped proxy check — for an
 * endpoint the deployed tool would in fact send through the proxy, which is
 * the silent-`NO_PROXY`-mistake class this validation exists to catch
 * (SPEC.md §7).
 */

export type NoProxyEntryIssue =
  | 'ok'
  | 'empty'
  | 'contains-scheme'
  | 'contains-port-with-wildcard'
  | 'invalid-hostname'
  | 'wildcard-not-leading';

/** One endpoint as `NO_PROXY` sees it: the host and the port it is declared on. */
export interface NoProxyTarget {
  host: string;
  port: number;
}

export interface NoProxyEntry {
  raw: string;
  issue: NoProxyEntryIssue;
  matchedTargets: readonly NoProxyTarget[];
}

const HOSTNAME_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const IPV4_CIDR = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;

function isValidHostname(text: string): boolean {
  if (text === '') return false;
  return text.split('.').every((label) => HOSTNAME_LABEL.test(label));
}

/** Split a trailing `:port` off an entry; `port` is `null` when it carries none. */
function splitPort(text: string): { base: string; port: number | null } {
  const colon = text.lastIndexOf(':');
  if (colon === -1) return { base: text, port: null };
  const portText = text.slice(colon + 1);
  if (!/^\d+$/.test(portText)) return { base: text, port: null };
  return { base: text.slice(0, colon), port: Number(portText) };
}

function classify(entry: string): NoProxyEntryIssue {
  if (entry === '') return 'empty';
  if (entry.includes('://')) return 'contains-scheme';

  const wildcardIndex = entry.indexOf('*');
  if (wildcardIndex !== -1 && wildcardIndex !== 0) return 'wildcard-not-leading';

  const hasWildcard = wildcardIndex === 0;
  const { base, port } = splitPort(entry);
  if (hasWildcard && port !== null) return 'contains-port-with-wildcard';

  if (IPV4_CIDR.test(base)) return 'ok';

  // Strip a leading wildcard/dot before validating the remaining hostname
  // labels; a bare "*" (match everything) has nothing left to validate.
  let hostPart = base;
  if (hasWildcard) hostPart = base.slice(1);
  if (hostPart.startsWith('.')) hostPart = hostPart.slice(1);
  if (hostPart === '') return hasWildcard ? 'ok' : 'invalid-hostname';

  return isValidHostname(hostPart) ? 'ok' : 'invalid-hostname';
}

/**
 * Which declared profile endpoints a syntactically valid (`ok`) entry would
 * bypass the proxy for.
 *
 * An entry that carries a port matches only targets on that port; an entry
 * without one matches the host on every port it is declared on.
 *
 * CIDR entries (`10.0.0.0/8`) validate as `ok` but never match anything here:
 * `targets` are hostnames, not resolved addresses, and this is a pure
 * layer with no resolver — matching a CIDR against a hostname would require
 * an IP that is not available yet. Judgment call, noted for the reviewer.
 */
function matches(entry: string, targets: readonly NoProxyTarget[]): readonly NoProxyTarget[] {
  if (IPV4_CIDR.test(entry)) return [];

  const { base, port } = splitPort(entry);
  const onPort = port === null ? targets : targets.filter((target) => target.port === port);

  if (base === '*') return [...onPort];

  if (base.startsWith('*')) return matchSuffix(base.slice(1), onPort);

  if (base.startsWith('.')) return matchSuffix(base, onPort);

  return onPort.filter((target) => target.host.toLowerCase() === base.toLowerCase());
}

/** Shared by leading-`.` and leading-`*` entries: both are a domain-suffix match. */
function matchSuffix(suffix: string, targets: readonly NoProxyTarget[]): readonly NoProxyTarget[] {
  if (suffix === '') return [...targets];
  const lower = suffix.toLowerCase();
  if (!lower.startsWith('.')) {
    return targets.filter((target) => target.host.toLowerCase().endsWith(lower));
  }
  const bareDomain = lower.slice(1);
  return targets.filter((target) => {
    const host = target.host.toLowerCase();
    return host === bareDomain || host.endsWith(lower);
  });
}

export function validateNoProxy(rawValue: string, targets: readonly NoProxyTarget[]): NoProxyEntry[] {
  if (rawValue.trim() === '') return [];

  return rawValue.split(',').map((piece) => {
    const raw = piece.trim();
    const issue = classify(raw);
    const matchedTargets = issue === 'ok' ? matches(raw, targets) : [];
    return { raw, issue, matchedTargets };
  });
}
