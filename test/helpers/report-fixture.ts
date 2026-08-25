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
