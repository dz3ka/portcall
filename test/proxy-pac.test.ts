import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { MAX_SCRIPT_BYTES, evaluatePac } from '../src/probes/proxy/pac.ts';
import type { PacContext } from '../src/probes/proxy/pac.ts';

/**
 * Fixture-driven: real PAC (JavaScript) script text under
 * `test/fixtures/pac/*.js`, matching the "these are real JS text, not inline
 * test strings" instruction for the scenarios that benefit from reading as a
 * standalone script. A few scenarios (oversized script, isolation-between-
 * runs, globals-not-exposed) are inline since generating/asserting them needs
 * to be co-located with the assertion.
 */

const PAC_DIR = join(import.meta.dirname, 'fixtures', 'pac');
const TIMEOUT_MS = 200;

async function pacFixture(name: string): Promise<string> {
  return readFile(join(PAC_DIR, name), 'utf8');
}

function baseCtx(overrides: Partial<PacContext> = {}): PacContext {
  return {
    scriptText: '',
    resolvedTarget: null,
    myAddress: '10.0.0.5',
    now: new Date('2026-08-25T00:00:00Z'),
    ...overrides,
  };
}

describe('evaluatePac: basic verdicts', () => {
  it('always-DIRECT script returns direct', async () => {
    const scriptText = await pacFixture('always-direct.js');
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('always-proxy script returns the parsed host/port', async () => {
    const scriptText = await pacFixture('always-proxy.js');
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: 'proxy.corp.internal', port: 8080 });
  });

  it('conditional routing: dnsDomainIs branch', async () => {
    const scriptText = await pacFixture('conditional-routing.js');
    const verdict = evaluatePac(
      'https://svc.internal.example.com/',
      'svc.internal.example.com',
      baseCtx({ scriptText }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('conditional routing: shExpMatch branch', async () => {
    const scriptText = await pacFixture('conditional-routing.js');
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: 'proxy.corp.internal', port: 8080 });
  });

  it('conditional routing: fallback branch', async () => {
    const scriptText = await pacFixture('conditional-routing.js');
    const verdict = evaluatePac('https://other.example.org/', 'other.example.org', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: 'fallback.corp.internal', port: 3128 });
  });
});

describe('evaluatePac: sandbox hardening', () => {
  it('kills an infinite loop within the timeout and returns error, without hanging the suite', async () => {
    const scriptText = await pacFixture('hostile-infinite-loop.js');
    const startedAt = Date.now();
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    const elapsedMs = Date.now() - startedAt;
    expect(verdict).toEqual({ kind: 'error' });
    // Generous multiple of TIMEOUT_MS so this stays robust under CI jitter
    // while still proving the loop did not run to the test's own timeout.
    expect(elapsedMs).toBeLessThan(TIMEOUT_MS * 10);
  });

  it('rejects an oversized script before compiling it', () => {
    const oversized = `function FindProxyForURL(url, host) { return "DIRECT"; } // ${'x'.repeat(MAX_SCRIPT_BYTES + 1)}`;
    expect(oversized.length).toBeGreaterThan(MAX_SCRIPT_BYTES);
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText: oversized }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });

  it('blocks eval() via codeGeneration: { strings: false }', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        eval("1 + 1");
        return "DIRECT";
      }
    `;
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });

  it('blocks the Function constructor via codeGeneration: { strings: false }', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var f = new Function("return 1");
        return "DIRECT";
      }
    `;
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });

  it('exposes no Node globals (require/process/global/Buffer) inside the sandbox', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var leaked =
          typeof process !== "undefined" ||
          typeof require !== "undefined" ||
          typeof global !== "undefined" ||
          typeof Buffer !== "undefined";
        return leaked ? "PROXY leaked:1" : "DIRECT";
      }
    `;
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('gives each call a fresh context: state does not leak across runs', () => {
    const first = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText: 'var leaked = "yes"; function FindProxyForURL(url, host) { return "DIRECT"; }' }),
      TIMEOUT_MS,
    );
    const second = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({
        scriptText:
          'function FindProxyForURL(url, host) { return (typeof leaked === "undefined") ? "DIRECT" : "PROXY leaked:1"; }',
      }),
      TIMEOUT_MS,
    );
    expect(first).toEqual({ kind: 'direct' });
    expect(second).toEqual({ kind: 'direct' });
  });

  it('a syntactically invalid script errors without leaking script content', async () => {
    const scriptText = await pacFixture('syntax-error.js');
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
    // `error` is a closed one-field variant, so there is structurally nowhere
    // for the script body to have leaked into - assert that directly too.
    expect(Object.keys(verdict)).toEqual(['kind']);
    expect(JSON.stringify(verdict)).not.toContain('invalid syntax');
  });
});

describe('evaluatePac: the DNS side-channel rule (SPEC.md §4.3)', () => {
  it('dnsResolve on a hostname that is NOT the pre-resolved target returns null, never a real lookup', async () => {
    const scriptText = await pacFixture('dns-sidechannel-probe.js');
    const verdict = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText, resolvedTarget: { host: 'api.example.com', addresses: ['93.184.216.34'] } }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'proxy', host: 'blocked-sidechannel', port: 1 });
  });

  it('dnsResolve on the pre-resolved target host does answer', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var addr = dnsResolve("api.example.com");
        return addr === null ? "PROXY no-answer:1" : ("PROXY " + addr + ":2");
      }
    `;
    const verdict = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText, resolvedTarget: { host: 'api.example.com', addresses: ['93.184.216.34'] } }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'proxy', host: '93.184.216.34', port: 2 });
  });

  it('isResolvable follows the same restriction as dnsResolve', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        return isResolvable("somehost.internal") ? "PROXY leaked:1" : "DIRECT";
      }
    `;
    const verdict = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText, resolvedTarget: { host: 'api.example.com', addresses: ['93.184.216.34'] } }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('isInNet against a non-target host never resolves it: false, not a real lookup', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var inNet = isInNet("somehost.internal", "93.184.0.0", "255.255.0.0");
        return inNet ? "PROXY leaked:1" : "DIRECT";
      }
    `;
    const verdict = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText, resolvedTarget: { host: 'api.example.com', addresses: ['93.184.216.34'] } }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'direct' });
  });

  it('isInNet against the target host, and against a literal IP, both work', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var targetMatch = isInNet("api.example.com", "93.184.0.0", "255.255.0.0");
        var literalMatch = isInNet("10.5.6.7", "10.0.0.0", "255.0.0.0");
        return (targetMatch && literalMatch) ? "PROXY both:1" : "PROXY neither:2";
      }
    `;
    const verdict = evaluatePac(
      'https://api.example.com/',
      'api.example.com',
      baseCtx({ scriptText, resolvedTarget: { host: 'api.example.com', addresses: ['93.184.216.34'] } }),
      TIMEOUT_MS,
    );
    expect(verdict).toEqual({ kind: 'proxy', host: 'both', port: 1 });
  });

  it('with no resolvedTarget at all, dnsResolve/isResolvable/isInNet all answer negatively', () => {
    const scriptText = `
      function FindProxyForURL(url, host) {
        var any = dnsResolve("api.example.com") !== null || isResolvable("api.example.com") || isInNet("api.example.com", "0.0.0.0", "0.0.0.0");
        return any ? "PROXY leaked:1" : "DIRECT";
      }
    `;
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText, resolvedTarget: null }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'direct' });
  });
});

describe('evaluatePac: myIpAddress and misc verdict parsing', () => {
  it('myIpAddress() returns ctx.myAddress, not a live interface lookup', () => {
    const scriptText = 'function FindProxyForURL(url, host) { return "PROXY " + myIpAddress() + ":9"; }';
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText, myAddress: '172.20.0.9' }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'proxy', host: '172.20.0.9', port: 9 });
  });

  it('an unparseable but non-throwing return value is unresolved, not error', () => {
    const scriptText = 'function FindProxyForURL(url, host) { return "SOCKS5 socks.corp.internal:1080"; }';
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'unresolved' });
  });

  it('a script that returns nothing (undefined) is unresolved', () => {
    const scriptText = 'function FindProxyForURL(url, host) {}';
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'unresolved' });
  });

  it('a missing FindProxyForURL is an error, not a crash', () => {
    const scriptText = 'var notTheEntryPoint = 1;';
    const verdict = evaluatePac('https://api.example.com/', 'api.example.com', baseCtx({ scriptText }), TIMEOUT_MS);
    expect(verdict).toEqual({ kind: 'error' });
  });
});
