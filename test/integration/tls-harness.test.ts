import { beforeAll, describe, expect, it } from 'vitest';
import type { Finding } from '../../src/model/finding.ts';
import type { LoadedProfile } from '../../src/profiles/schema.ts';
import { runDns } from '../../src/probes/dns/index.ts';
import { runProxy } from '../../src/probes/proxy/index.ts';
import { runTls } from '../../src/probes/tls/index.ts';
import { runTruststore } from '../../src/probes/truststore/index.ts';
import {
  evidenceValue,
  findingById,
  harnessContext,
  harnessProfile,
  HARNESS_PROXIES,
  idsOf,
  requireHarness,
  withEnv,
} from './harness.ts';

/**
 * The hostile network, end to end (SPEC.md §10, ADR-0025).
 *
 * Every other test in this repo hands a probe a recorded chain or a stubbed
 * seam. This one hands it a real socket to a real proxy that is really
 * re-signing traffic, and asserts on the finding ids and severities that come
 * back — which CLAUDE.md treats as API, so this file is also their contract
 * test against live behaviour rather than against a fixture somebody wrote to
 * match the code.
 *
 * The four network conditions SPEC.md §10 lists, in its order, then a fifth
 * that section does not list because it is a property of the machine rather
 * than of the network: a root the OS trusts and Node does not, planted by the
 * container at start (ADR-0041). One `describe` each.
 * The probes are called directly rather than through the built CLI: a failure
 * should point at `runTls`, not at argv parsing, and the CLI has its own
 * coverage in the guardrail suite. Nothing here sleeps, polls or retries —
 * readiness is a compose healthcheck, and `requireHarness` fails loudly if the
 * stack is not there at all.
 */

beforeAll(() => {
  requireHarness();
});

/** All findings with this id. Several scenarios legitimately produce two — one per path. */
function allById(findings: readonly Finding[], id: string): Finding[] {
  return findings.filter((finding) => finding.id === id);
}

/** The harness profile with only the endpoints on `ports`, for scenarios that need one target. */
function profileWithPorts(ports: readonly number[]): LoadedProfile {
  const loaded = harnessProfile();
  return {
    ...loaded,
    profile: {
      ...loaded.profile,
      endpoints: loaded.profile.endpoints.filter((endpoint) => ports.includes(endpoint.port)),
    },
  };
}

describe('mitmproxy re-signing with a generated root', () => {
  it('reports a private root on both paths and a different chain through the proxy', async () => {
    const findings = await runTls(harnessContext(profileWithPorts([443])), undefined, {
      HTTPS_PROXY: HARNESS_PROXIES.intercepting,
    });

    // Both captures must have produced a chain. If either failed, the
    // `tls.capture-failed-*` id in this message says which phase died, which is
    // the first thing to take to the service logs.
    expect(idsOf(findings).filter((id) => id.startsWith('tls.capture-failed'))).toEqual([]);

    const privateRoots = allById(findings, 'tls.private-root');
    expect(privateRoots).toHaveLength(2);
    // The harness profile sets `interception_tolerated: false` on a required
    // endpoint, so this is the strict branch: a blocker, exit code 2.
    for (const finding of privateRoots) expect(finding.severity).toBe('blocker');
    expect(privateRoots.map((finding) => evidenceValue(finding, 'connection')).sort()).toEqual(['direct', 'proxy']);

    // The observation that needs no trust judgement at all: two different
    // certificates for one endpoint, one of them the proxy's.
    const intercepted = findingById(findings, 'tls.intercepted-via-proxy');
    expect(intercepted.severity).toBe('degraded');
    expect(intercepted.remediation).toBeTruthy();

    // The proxied leaf is signed by mitmproxy's own generated CA and the direct
    // one by the origin image's root. Naming the issuer is the whole difference
    // between "interception detected" and a finding somebody can act on.
    const issuers = privateRoots.map((finding) => evidenceValue(finding, 'root issuer') ?? '');
    expect(issuers.some((issuer) => issuer.toLowerCase().includes('mitmproxy'))).toBe(true);
    expect(issuers.some((issuer) => issuer.includes('Portcall Harness Origin Root'))).toBe(true);
  });

  it('does not mistake the harness origin for a publicly rooted endpoint', async () => {
    const findings = await runTls(harnessContext(profileWithPorts([443])), undefined, {});

    const ids = idsOf(findings);
    expect(ids).toContain('tls.private-root');
    expect(ids).not.toContain('tls.public-root');
    // The origin serves leaf + root, so the anchor is presented and the verdict
    // is conclusive rather than the ADR-0021 "could not tell".
    expect(ids).not.toContain('tls.root-indeterminate');
    // No proxy in the environment means one capture, so there is nothing to
    // compare and the comparison correctly says nothing.
    expect(ids).not.toContain('tls.intercepted-via-proxy');
    expect(ids).not.toContain('tls.chain-consistent');
  });
});

describe('squid demanding Basic authentication', () => {
  it('names the scheme demanded and never authenticates', async () => {
    const findings = await withEnv({ HTTPS_PROXY: HARNESS_PROXIES.authenticating, HTTP_PROXY: undefined }, () =>
      runProxy(harnessContext(profileWithPorts([443]))),
    );

    const challenge = findingById(findings, 'proxy.auth-required');
    expect(challenge.severity).toBe('degraded');
    expect(evidenceValue(challenge, 'auth scheme')).toBe('Basic');

    // SPEC.md §4 as a test rather than a promise: the credential squid was
    // built with appears nowhere in what portcall produced, because portcall
    // never had it and never asked for it.
    const serialised = JSON.stringify(findings);
    expect(serialised).not.toContain('harness-user');
    expect(serialised).not.toMatch(/authorization/i);
  });

  it('stops the TLS capture at the challenge instead of answering it', async () => {
    const findings = await runTls(harnessContext(profileWithPorts([443])), undefined, {
      HTTPS_PROXY: HARNESS_PROXIES.authenticating,
    });

    const tunnel = findingById(findings, 'tls.capture-failed-tunnel');
    // `unknown`, not `blocker`: the proxy probe reports this at the severity it
    // deserves, and counting it twice would make the summary lie about how much
    // is wrong.
    expect(tunnel.severity).toBe('unknown');
    expect(evidenceValue(tunnel, 'code')).toBe('HTTP_407');
    expect(evidenceValue(tunnel, 'connection')).toBe('proxy');

    // The direct path is untouched by the proxy's refusal, so the chain is
    // still captured and still judged.
    expect(idsOf(findings)).toContain('tls.private-root');
  });
});

describe('a resolver answering split-horizon', () => {
  it('reports a public name resolving to an internal address', async () => {
    const findings = await runDns(harnessContext(profileWithPorts([443])));

    const split = findingById(findings, 'dns.split-horizon');
    expect(split.severity).toBe('degraded');
    expect(evidenceValue(split, 'host')).toBe('api.anthropic.com');
    expect(evidenceValue(split, 'address')).toBe('10.31.0.20');
    // Not collapsed into a resolution failure: the name resolved perfectly
    // well, it just resolved somewhere a public name has no business resolving.
    expect(idsOf(findings)).not.toContain('dns.resolve-failed');
  });
});

describe('a proxy that refuses to tunnel a non-443 port', () => {
  it('reports the refusal as rejected, not as an auth challenge or a transport failure', async () => {
    const findings = await withEnv(
      { HTTPS_PROXY: HARNESS_PROXIES.refusing, HTTP_PROXY: HARNESS_PROXIES.refusing },
      () => runProxy(harnessContext(profileWithPorts([8080]))),
    );

    const rejected = findingById(findings, 'proxy.connect-rejected');
    // Capped to `degraded` because the 8080 endpoint is optional in the harness
    // profile — the cap is part of the API this suite holds.
    expect(rejected.severity).toBe('degraded');
    expect(rejected.remediation).toBeTruthy();

    // The four failure classes CLAUDE.md forbids collapsing into one another.
    // A refusal is not a challenge, a closed port, a timeout or a bad name.
    const ids = idsOf(findings);
    expect(ids).not.toContain('proxy.auth-required');
    expect(ids).not.toContain('proxy.connect-refused');
    expect(ids).not.toContain('proxy.connect-timeout');
    expect(ids).not.toContain('proxy.connect-dns-failure');
  });
});

/**
 * The only place the whole chain runs live.
 *
 * Every other assertion on the cross-check hands `crossCheck` a fixture's idea
 * of what `tls` observed. Here the intercepting proxy really re-signs, the
 * container really planted mitmproxy's generated root in its own OS trust store
 * at start (ADR-0041), and the promotion to `blocker` happens because the `tls`
 * probe *watched that exact root terminate a chain* - which is the claim the
 * severity makes to a reader, and the one a stubbed `observedAnchors` cannot
 * substantiate. The two probes share one context on purpose: that field is the
 * seam between them (ADR-0034), and a second context would quietly turn this
 * into the fixture test it is meant not to be.
 */
describe('a root this machine trusts that node does not', () => {
  it('promotes the missing root to a blocker when the tls probe observed it intercepting', async () => {
    const context = harnessContext(profileWithPorts([443]));
    await runTls(context, undefined, { HTTPS_PROXY: HARNESS_PROXIES.intercepting });
    const findings = await runTruststore(context);

    // The planted store has to have been read, or the cross-check below would
    // be suppressed and every assertion after it would pass vacuously.
    expect(findingById(findings, 'truststore.os.read').severity).toBe('ok');

    const missing = findingById(findings, 'truststore.node.missing-root');
    expect(missing.severity).toBe('blocker');
    // Measured, not assumed: mitmproxy 11.0.2 does not send its CA with the leaf,
    // so the correlation is by issuer name and never by bytes.
    expect(evidenceValue(missing, 'match')).toBe('issuer-name');
    expect(evidenceValue(missing, 'connection')).toBe('proxy');
    expect(evidenceValue(missing, 'host')).toBe('api.anthropic.com');
    expect(missing.remediation).toBeTruthy();

    // ADR-0038's ordering, live: the correlated anchor is the one a reader
    // needs first, so it leads the list rather than being truncated out of it
    // by whatever else the OS store happens to hold.
    const anchors = missing.evidence.filter((item) => item.label === 'anchor').map((item) => item.value);
    expect(anchors[0]?.toLowerCase()).toContain('mitmproxy');
  });
});
