import type { Finding } from '../../src/model/finding.ts';
import type { Report } from '../../src/model/report.ts';
import { REPORT_SCHEMA_VERSION } from '../../src/model/report.ts';
import { summarise, sortFindings } from '../../src/engine/rollup.ts';

/**
 * Shared builder for a plausible `Report`, used by the renderer and redaction
 * test files. Each test file still exercises its own assertions independently
 * (per the brief: "each test file should stand alone") — this only avoids
 * re-typing the same report shape everywhere.
 */
export function buildReport(overrides: Partial<Report> = {}, findings: Finding[] = []): Report {
  const sorted = sortFindings(findings);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: 'portcall', version: '0.1.0' },
    generatedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 12,
    platform: { os: 'linux', arch: 'x64', runtime: 'node', runtimeVersion: '24.0.0' },
    profile: {
      name: 'Fixture profile',
      id: 'fixture',
      source: 'builtin',
      endpoints: 2,
      runtimes: ['node'],
    },
    redacted: false,
    summary: summarise(sorted),
    findings: sorted,
    ...overrides,
  };
}

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'fixture.finding',
    probe: 'fixture',
    severity: 'ok',
    title: 'Fixture finding',
    evidence: [],
    ...overrides,
  };
}

/**
 * The golden report: one finding per `Severity`, and evidence covering every
 * `EvidenceKind` exactly once across the four.
 *
 * It exists so two different tests can assert against the *same* document —
 * `report-html.test.ts` pins its rendered JSON byte for byte against
 * `test/fixtures/report/golden-report.json`, and the html-self-contained
 * guardrail scans its HTML render. A report that exercises every kind is worth
 * more to both than the one-finding fixtures above, because the kinds are
 * exactly where redaction and escaping decide what reaches a reader.
 *
 * Everything here is fixed: `buildReport` supplies a constant `generatedAt`,
 * and the tests redact with a constant salt, so the tokens are reproducible.
 * Keep the `public`/`text`/`number` values free of `http(s)` URLs — those three
 * kinds cross redaction verbatim, and the guardrail asserts that the only
 * absolute URL in the document is a `docs` link inside an `<a href>`.
 */
export function goldenReport(): Report {
  return buildReport(
    {
      durationMs: 1843,
      platform: { os: 'darwin', arch: 'arm64', runtime: 'node', runtimeVersion: '22.18.0' },
      profile: {
        name: 'Golden fixture profile',
        id: 'golden',
        source: 'builtin',
        endpoints: 3,
        runtimes: ['node', 'java'],
      },
    },
    [
      finding({
        id: 'truststore.node.missing-root',
        probe: 'truststore',
        severity: 'blocker',
        title: 'Node does not trust a root this machine trusts',
        evidence: [
          { label: 'endpoint', value: 'api.internal.example', kind: 'hostname' },
          { label: 'resolved address', value: '10.31.0.9', kind: 'ip' },
          { label: 'anchor', value: 'CN=Acme Corp Internal Root, O=Acme Corp', kind: 'dn' },
        ],
        remediation: 'Export the root and point NODE_EXTRA_CA_CERTS at it, then re-run.',
        docs: 'https://example.com/docs/truststore-missing-root',
      }),
      finding({
        id: 'tls.intercepted-via-proxy',
        probe: 'tls',
        severity: 'degraded',
        title: 'The chain seen through the proxy is not the chain seen directly',
        evidence: [
          { label: 'pac url', value: 'http://wpad.internal.example/proxy.pac', kind: 'url' },
          { label: 'leaf serial', value: '04:9e:2b:11', kind: 'serial' },
          { label: 'bundle', value: '/etc/ssl/certs/ca-certificates.crt', kind: 'path' },
        ],
        remediation: 'Add the interception CA to every runtime bundle the profile declares.',
        docs: 'https://example.com/docs/tls-intercepted',
      }),
      finding({
        id: 'proxy.pac-inconclusive',
        probe: 'proxy',
        severity: 'unknown',
        title: 'The PAC script returned no usable verdict',
        evidence: [
          { label: 'proxy user', value: 'svc-buildbot', kind: 'username' },
          { label: 'phase', value: 'evaluation timed out', kind: 'text' },
        ],
      }),
      finding({
        id: 'egress.reachable',
        probe: 'egress',
        severity: 'ok',
        title: 'Every required endpoint answered',
        evidence: [
          { label: 'endpoint', value: 'api.anthropic.com', kind: 'public' },
          { label: 'endpoints reached', value: '3', kind: 'number' },
        ],
      }),
    ],
  );
}
