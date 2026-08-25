import { describe, expect, it } from 'vitest';
import { DOH_PORT, NetworkGuard, NetworkPolicyError } from '../src/net/guard.ts';
import type { Profile } from '../src/profiles/schema.ts';

function profile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'Fixture',
    endpoints: [
      { host: 'api.example.com', port: 443, purpose: 'inference', required: true, expect_streaming: false },
      { host: 'registry.example.com', port: 443, purpose: 'updates', required: false, expect_streaming: false },
    ],
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: true },
    ...overrides,
  };
}

describe('NetworkGuard', () => {
  it('pre-permits every profile endpoint host:port', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('api.example.com', 443)).toBe(true);
    expect(guard.isAllowed('registry.example.com', 443)).toBe(true);
  });

  it('is case-insensitive on host', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('API.EXAMPLE.COM', 443)).toBe(true);
  });

  it('denies a host not named in the profile', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('evil.example.com', 443)).toBe(false);
  });

  it('denies the right host on the wrong port', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('api.example.com', 8080)).toBe(false);
  });

  it('assertAllowed throws NetworkPolicyError with host and port for a denied target', () => {
    const guard = new NetworkGuard(profile());
    expect(() => guard.assertAllowed('evil.example.com', 443)).toThrow(NetworkPolicyError);
    try {
      guard.assertAllowed('evil.example.com', 443);
      throw new Error('expected assertAllowed to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(NetworkPolicyError);
      if (error instanceof NetworkPolicyError) {
        expect(error.host).toBe('evil.example.com');
        expect(error.port).toBe(443);
      }
    }
  });

  it('assertAllowed does not throw for an allowed target', () => {
    const guard = new NetworkGuard(profile());
    expect(() => guard.assertAllowed('api.example.com', 443)).not.toThrow();
  });

  it('permit() admits a runtime-discovered host explicitly, with a reason', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('proxy.internal', 8080)).toBe(false);
    guard.permit('proxy.internal', 8080, 'discovered via WPAD');
    expect(guard.isAllowed('proxy.internal', 8080)).toBe(true);
  });

  it('permit() adds a second port for an already-permitted host', () => {
    const guard = new NetworkGuard(profile());
    guard.permit('api.example.com', 8443, 'alt port');
    expect(guard.isAllowed('api.example.com', 443)).toBe(true);
    expect(guard.isAllowed('api.example.com', 8443)).toBe(true);
  });

  it('permitted() lists every allowed host sorted, for report disclosure', () => {
    const guard = new NetworkGuard(profile());
    guard.permit('proxy.internal', 8080, 'discovered via WPAD');
    const hosts = guard.permitted().map((entry) => entry.host);
    expect(hosts).toEqual(['api.example.com', 'proxy.internal', 'registry.example.com']);
  });

  it('assertHostAllowed throws NetworkPolicyError for a host the profile never names', () => {
    const guard = new NetworkGuard(profile());
    expect(() => guard.assertHostAllowed('evil.example.com')).toThrow(NetworkPolicyError);
  });

  it('assertHostAllowed passes for a profile host on a port the profile did not declare', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isAllowed('api.example.com', 8080)).toBe(false);
    expect(() => guard.assertHostAllowed('api.example.com')).not.toThrow();
  });

  it('isHostAllowed answers on host scope alone', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isHostAllowed('api.example.com')).toBe(true);
    expect(guard.isHostAllowed('evil.example.com')).toBe(false);
  });

  it('isHostAllowed normalises case and surrounding whitespace like permit()', () => {
    const guard = new NetworkGuard(profile());
    expect(guard.isHostAllowed('  API.Example.COM  ')).toBe(true);
  });

  it('pre-permits every declared DoH resolver on 443 and on no other port', () => {
    const guard = new NetworkGuard(profile({ doh_resolvers: ['cloudflare-dns.com', 'dns.google'] }));
    expect(guard.isAllowed('cloudflare-dns.com', DOH_PORT)).toBe(true);
    expect(guard.isAllowed('dns.google', DOH_PORT)).toBe(true);
    expect(guard.isAllowed('cloudflare-dns.com', 853)).toBe(false);
    expect(guard.isAllowed('dns.google', 80)).toBe(false);
  });
});
