import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { profileSchema } from '../src/profiles/schema.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures', 'profiles');

async function fixture(name: string): Promise<string> {
  return readFile(join(FIXTURES, name), 'utf8');
}

/** A minimal valid profile body, so each case varies exactly one field. */
function raw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'Fixture AI tool',
    endpoints: [{ host: 'api.example.com', port: 443, purpose: 'model inference' }],
    runtimes: ['node'],
    ...overrides,
  };
}

describe('profileSchema doh_resolvers', () => {
  it('accepts a profile that declares resolvers and round-trips them', async () => {
    const text = await fixture('doh-resolvers.yaml');
    const profile = profileSchema.parse(parseYaml(text));
    expect(profile.doh_resolvers).toEqual(['cloudflare-dns.com', 'dns.google']);
  });

  it('defaults to an empty array when a profile omits the field', async () => {
    const text = await fixture('valid.yaml');
    const profile = profileSchema.parse(parseYaml(text));
    expect(profile.doh_resolvers).toEqual([]);
  });

  it('rejects more than four resolvers', () => {
    const result = profileSchema.safeParse(
      raw({ doh_resolvers: ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com', 'e.example.com'] }),
    );
    expect(result.success).toBe(false);
  });

  it('rejects a DoH URL: the seam takes {host,port,useTls}, never a path', () => {
    const result = profileSchema.safeParse(raw({ doh_resolvers: ['https://dns.google/dns-query'] }));
    expect(result.success).toBe(false);
  });

  it('rejects host:port: RFC 8484 fixes the port at 443', () => {
    const result = profileSchema.safeParse(raw({ doh_resolvers: ['dns.google:443'] }));
    expect(result.success).toBe(false);
  });
});

describe('profileSchema proxy.pac_url', () => {
  it('accepts a valid PAC URL', () => {
    const result = profileSchema.safeParse(raw({ proxy: { pac_url: 'http://wpad.example.com/proxy.pac' } }));
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.proxy?.pac_url).toBe('http://wpad.example.com/proxy.pac');
    }
  });

  it('rejects an invalid PAC URL', () => {
    const result = profileSchema.safeParse(raw({ proxy: { pac_url: 'not-a-url' } }));
    expect(result.success).toBe(false);
  });

  it('is still valid when the proxy field is omitted entirely', () => {
    const result = profileSchema.safeParse(raw());
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.proxy).toBeUndefined();
    }
  });
});
