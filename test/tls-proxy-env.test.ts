import { describe, expect, it } from 'vitest';
import { discoverEnvProxy } from '../src/probes/tls/proxy-env.ts';

/**
 * The `tls` probe's proxy discovery (ADR-0023): the environment variables and
 * nothing else. The precedence and the parsing are the proxy probe's own for
 * its env-var leg — `HTTPS_PROXY` first because every capture this probe makes
 * is a TLS capture — and the tests below pin both, plus the invariant that
 * matters most: a credential embedded in the variable is never read.
 */

describe('discoverEnvProxy', () => {
  it('reads HTTPS_PROXY in preference to HTTP_PROXY, because every capture is TLS', () => {
    expect(discoverEnvProxy({ HTTPS_PROXY: 'http://secure.proxy.test:3128', HTTP_PROXY: 'http://plain.proxy.test:8080' }))
      .toEqual({ host: 'secure.proxy.test', port: 3128 });
  });

  it('falls back to HTTP_PROXY when HTTPS_PROXY is unset', () => {
    expect(discoverEnvProxy({ HTTP_PROXY: 'http://plain.proxy.test:8080' })).toEqual({
      host: 'plain.proxy.test',
      port: 8080,
    });
  });

  it('accepts the lowercase spelling, which is the one curl documents', () => {
    expect(discoverEnvProxy({ https_proxy: 'http://proxy.test:3128' })).toEqual({ host: 'proxy.test', port: 3128 });
  });

  it('defaults the port by scheme when the value carries none', () => {
    expect(discoverEnvProxy({ HTTPS_PROXY: 'http://proxy.test' })).toEqual({ host: 'proxy.test', port: 80 });
    expect(discoverEnvProxy({ HTTPS_PROXY: 'https://proxy.test' })).toEqual({ host: 'proxy.test', port: 443 });
  });

  it('accepts a bare host:port, which is what people actually set', () => {
    expect(discoverEnvProxy({ HTTPS_PROXY: 'proxy.test:3128' })).toEqual({ host: 'proxy.test', port: 3128 });
  });

  it('reads the host and port out of a value with embedded credentials, and nothing else', () => {
    const discovered = discoverEnvProxy({ HTTPS_PROXY: 'http://alice:hunter2@proxy.test:3128' });

    expect(discovered).toEqual({ host: 'proxy.test', port: 3128 });
    // Belt and braces: no key of the result may carry the userinfo (SPEC.md §4).
    expect(JSON.stringify(discovered)).not.toMatch(/alice|hunter2/);
  });

  it('treats unset, empty and whitespace-only as no proxy at all', () => {
    expect(discoverEnvProxy({})).toBeNull();
    expect(discoverEnvProxy({ HTTPS_PROXY: '', HTTP_PROXY: '' })).toBeNull();
    expect(discoverEnvProxy({ HTTPS_PROXY: '   ' })).toBeNull();
  });

  it('returns null for a value that is not a usable proxy URL, rather than guessing', () => {
    expect(discoverEnvProxy({ HTTPS_PROXY: 'http://' })).toBeNull();
    expect(discoverEnvProxy({ HTTPS_PROXY: '://nonsense' })).toBeNull();
  });
});
