/**
 * DNS answer analysis (M1).
 *
 * Pure: no resolver, no sockets, no `node:*` at all. The address parsing below
 * is written by hand rather than delegated to `node:net`'s `isIP`, because the
 * guardrail test (`test/guardrails/no-network-outside-allowlist.test.ts`) lets
 * only `src/net/` import a networking module — and reaching for one here to
 * borrow a *string* function would put a hole in that rule for no reason.
 * Range-checking four integers is not the hard part of this project.
 */

/**
 * What a resolved address tells us about the network.
 *
 * The split that matters is `sinkhole` vs `private`. A sinkhole answer
 * (`0.0.0.0`, loopback) is a *deliberate block*: someone configured DNS to
 * refuse this name, and nothing will connect. A private answer is usually
 * legitimate — a corporate VIP, a split-horizon zone pointing at an internal
 * mirror — and the tool may well work fine through it. One becomes a blocker,
 * the other at most a degraded finding, so they are never the same class.
 */
export type AddressClass = 'public' | 'private' | 'sinkhole' | 'malformed';

/**
 * A resolution at or over this takes long enough that a user notices it on
 * every request. Slow DNS is a real deployment problem (a stale forwarder, a
 * dead resolver in the list being tried first), so it is reported rather than
 * silently tolerated.
 */
export const SLOW_RESOLUTION_MS = 500;

interface Ipv4 {
  a: number;
  b: number;
  c: number;
  d: number;
}

type Ipv6Groups = readonly [number, number, number, number, number, number, number, number];

const IPV4_OCTET = /^(?:0|[1-9]\d{0,2})$/;
const IPV6_GROUP = /^[0-9a-fA-F]{1,4}$/;

/**
 * Strict dotted-quad parsing: exactly four octets, decimal digits only, no
 * leading zeros. `010.0.0.1` is rejected rather than guessed at, because
 * whether that leading zero means octal depends on who is reading it, and an
 * address we cannot read unambiguously is `malformed`, not `public`.
 */
function parseIpv4(text: string): Ipv4 | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;

  const octets: number[] = [];
  for (const part of parts) {
    if (!IPV4_OCTET.test(part)) return null;
    const value = Number.parseInt(part, 10);
    if (value > 255) return null;
    octets.push(value);
  }

  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
  return { a, b, c, d };
}

/** Parse one colon-separated run of hex groups. An empty run yields no groups. */
function parseHexGroups(segment: string): number[] | null {
  if (segment === '') return [];

  const groups: number[] = [];
  for (const token of segment.split(':')) {
    if (!IPV6_GROUP.test(token)) return null;
    groups.push(Number.parseInt(token, 16));
  }
  return groups;
}

/**
 * The runtime length check is the real validation; the eight `undefined`
 * comparisons only tell the compiler what it cannot see through
 * `noUncheckedIndexedAccess`.
 */
function toGroups(values: readonly number[]): Ipv6Groups | null {
  if (values.length !== 8) return null;

  const [a, b, c, d, e, f, g, h] = values;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
  if (e === undefined || f === undefined || g === undefined || h === undefined) return null;
  return [a, b, c, d, e, f, g, h];
}

function parseIpv6(text: string): Ipv6Groups | null {
  let body = text;

  // A trailing dotted-quad (`::ffff:10.0.0.1`, `fc00::1.2.3.4`) is rewritten to
  // its two hex groups first, so the rest of the parser only sees hex.
  if (body.includes('.')) {
    const lastColon = body.lastIndexOf(':');
    if (lastColon === -1) return null;
    const embedded = parseIpv4(body.slice(lastColon + 1));
    if (embedded === null) return null;
    const high = ((embedded.a << 8) | embedded.b).toString(16);
    const low = ((embedded.c << 8) | embedded.d).toString(16);
    body = `${body.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const halves = body.split('::');
  if (halves.length > 2) return null;

  const head = parseHexGroups(halves[0] ?? '');
  if (head === null) return null;

  if (halves.length === 1) return toGroups(head);

  const tail = parseHexGroups(halves[1] ?? '');
  if (tail === null) return null;
  // `::` must stand for at least one elided group, so a full eight either side
  // of it is not a valid compression.
  if (head.length + tail.length > 7) return null;

  const elided = new Array<number>(8 - head.length - tail.length).fill(0);
  return toGroups([...head, ...elided, ...tail]);
}

function classifyIpv4({ a, b }: Ipv4): AddressClass {
  // 0.0.0.0/8 and 127.0.0.0/8: the two answers a DNS sinkhole hands out.
  if (a === 0 || a === 127) return 'sinkhole';
  // RFC 1918, plus link-local (169.254/16) and carrier-grade NAT (100.64/10),
  // which show up in real corporate answers and are equally not the internet.
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 169 && b === 254) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'private';
  return 'public';
}

function classifyIpv6(groups: Ipv6Groups): AddressClass {
  const [first] = groups;

  // `::` (the v6 sinkhole answer) and `::1` (loopback)
  if (groups.every((group) => group === 0)) return 'sinkhole';
  if (groups[7] === 1 && groups.slice(0, 7).every((group) => group === 0)) return 'sinkhole';

  // fc00::/7 (unique local) and fe80::/10 (link-local)
  if ((first & 0xfe00) === 0xfc00) return 'private';
  if ((first & 0xffc0) === 0xfe80) return 'private';
  return 'public';
}

/** True for the `::ffff:0:0/96` IPv4-mapped range. */
function mappedIpv4(groups: Ipv6Groups): Ipv4 | null {
  const [first, second, third, fourth, fifth, sixth, seventh, eighth] = groups;
  if (first !== 0 || second !== 0 || third !== 0 || fourth !== 0 || fifth !== 0) return null;
  if (sixth !== 0xffff) return null;
  return { a: seventh >>> 8, b: seventh & 0xff, c: eighth >>> 8, d: eighth & 0xff };
}

/**
 * Classify one resolved address.
 *
 * An IPv4-mapped IPv6 address is unwrapped before it is judged: `::ffff:10.0.0.1`
 * *is* `10.0.0.1`, and reading it as a public v6 address would report a
 * split-horizon corporate answer as a clean internet answer.
 */
export function classifyAddress(address: string): AddressClass {
  const v4 = parseIpv4(address);
  if (v4 !== null) return classifyIpv4(v4);

  const v6 = parseIpv6(address);
  if (v6 === null) return 'malformed';

  const mapped = mappedIpv4(v6);
  return mapped === null ? classifyIpv6(v6) : classifyIpv4(mapped);
}
