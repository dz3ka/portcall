import { describe, expect, it } from 'vitest';
import { SLOW_RESOLUTION_MS, classifyAddress } from '../src/probes/dns/analyse.ts';
import type { AddressClass } from '../src/probes/dns/analyse.ts';

/**
 * One row per address, with the boundary of every range covered from both
 * sides: an off-by-one here reads as "your corporate DNS is sinkholing this
 * host" on someone else's network, which is the worst kind of wrong answer.
 */
const ADDRESSES: readonly (readonly [string, AddressClass])[] = [
  // sinkhole: a deliberate block, not a network topology fact
  ['0.0.0.0', 'sinkhole'],
  ['0.1.2.3', 'sinkhole'],
  ['0.255.255.255', 'sinkhole'],
  ['127.0.0.1', 'sinkhole'],
  ['127.255.255.255', 'sinkhole'],
  ['::', 'sinkhole'],
  ['::1', 'sinkhole'],
  ['0:0:0:0:0:0:0:1', 'sinkhole'],
  // 10.0.0.0/8
  ['9.255.255.255', 'public'],
  ['10.0.0.0', 'private'],
  ['10.255.255.255', 'private'],
  ['11.0.0.0', 'public'],
  // 100.64.0.0/10 (carrier-grade NAT)
  ['100.63.255.255', 'public'],
  ['100.64.0.0', 'private'],
  ['100.127.255.255', 'private'],
  ['100.128.0.0', 'public'],
  // 172.16.0.0/12
  ['172.15.255.255', 'public'],
  ['172.16.0.0', 'private'],
  ['172.31.255.255', 'private'],
  ['172.32.0.0', 'public'],
  // 169.254.0.0/16 (link-local)
  ['169.253.255.255', 'public'],
  ['169.254.0.0', 'private'],
  ['169.254.255.255', 'private'],
  ['169.255.0.0', 'public'],
  // 192.168.0.0/16
  ['192.167.255.255', 'public'],
  ['192.168.0.0', 'private'],
  ['192.168.255.255', 'private'],
  ['192.169.0.0', 'public'],
  // fc00::/7 and fe80::/10
  ['fbff:ffff::1', 'public'],
  ['fc00::', 'private'],
  ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'private'],
  ['fe00::1', 'public'],
  ['fe7f:ffff::1', 'public'],
  ['fe80::', 'private'],
  ['fe80::1%25', 'malformed'],
  ['febf:ffff::1', 'private'],
  ['fec0::1', 'public'],
  // IPv4-mapped IPv6 is unwrapped before it is judged
  ['::ffff:10.0.0.1', 'private'],
  ['::ffff:127.0.0.1', 'sinkhole'],
  ['::ffff:93.184.216.34', 'public'],
  ['::ffff:0a00:0001', 'private'],
  // public
  ['93.184.216.34', 'public'],
  ['1.1.1.1', 'public'],
  ['2606:4700:4700::1111', 'public'],
  ['2001:db8::', 'public'],
  // malformed: anything we cannot parse as an address at all
  ['not-an-ip', 'malformed'],
  ['999.1.1.1', 'malformed'],
  ['10.0.0', 'malformed'],
  ['10.0.0.1.2', 'malformed'],
  ['10.0.0.-1', 'malformed'],
  ['10.0.0.01', 'malformed'],
  ['10.0.0.1 ', 'malformed'],
  ['', 'malformed'],
  ['::ffff:999.1.1.1', 'malformed'],
  ['fc00:::1', 'malformed'],
  ['fc00::1::2', 'malformed'],
  ['fg00::1', 'malformed'],
  ['12345::1', 'malformed'],
  ['1:2:3:4:5:6:7:8:9', 'malformed'],
  ['1:2:3:4:5:6:7', 'malformed'],
];

describe('classifyAddress', () => {
  it.each(ADDRESSES)('classifies %s as %s', (address, expected) => {
    expect(classifyAddress(address)).toBe(expected);
  });

  it('reaches every AddressClass member', () => {
    const produced = [...new Set(ADDRESSES.map(([address]) => classifyAddress(address)))].sort();
    expect(produced).toEqual(['malformed', 'private', 'public', 'sinkhole']);
  });
});

describe('SLOW_RESOLUTION_MS', () => {
  it('is the 500ms boundary', () => {
    expect(SLOW_RESOLUTION_MS).toBe(500);
  });

  // The predicate the probe applies is `elapsedMs >= SLOW_RESOLUTION_MS`: at
  // the boundary a resolution is already slow. Pinned here so a later change to
  // the constant cannot quietly move the boundary a millisecond either way.
  it.each([
    [499, false],
    [500, true],
    [501, true],
  ])('treats %dms as slow=%s', (elapsedMs, slow) => {
    expect(elapsedMs >= SLOW_RESOLUTION_MS).toBe(slow);
  });
});
