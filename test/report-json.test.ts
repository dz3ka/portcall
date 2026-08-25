import { describe, expect, it } from 'vitest';
import { renderJson } from '../src/report/json.ts';
import { redact } from '../src/redact/index.ts';
import { REPORT_SCHEMA_VERSION } from '../src/model/report.ts';
import { buildReport, finding } from './helpers/report-fixture.ts';

describe('renderJson', () => {
  it('pins schemaVersion to REPORT_SCHEMA_VERSION', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    const parsed = JSON.parse(renderJson(report)) as { schemaVersion: number };
    expect(parsed.schemaVersion).toBe(REPORT_SCHEMA_VERSION);
  });

  it('produces stable, fixed key order at the top level', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    const keys = Object.keys(JSON.parse(renderJson(report)) as Record<string, unknown>);
    expect(keys).toEqual([
      'schemaVersion',
      'tool',
      'generatedAt',
      'durationMs',
      'redacted',
      'platform',
      'profile',
      'summary',
      'findings',
    ]);
  });

  it('produces stable key order regardless of source object property order', () => {
    const reportA = buildReport({ durationMs: 1, generatedAt: 'a' });
    const reportB = buildReport({ generatedAt: 'a', durationMs: 1 });
    const jsonA = renderJson(redact(reportA, { enabled: true, salt: 's' }));
    const jsonB = renderJson(redact(reportB, { enabled: true, salt: 's' }));
    expect(jsonA).toBe(jsonB);
  });

  it('produces stable key order for each finding', () => {
    const report = redact(
      buildReport({}, [finding({ remediation: 'fix it', docs: 'https://x' })]),
      { enabled: true, salt: 's' },
    );
    const parsed = JSON.parse(renderJson(report)) as {
      findings: Record<string, unknown>[];
    };
    expect(Object.keys(parsed.findings[0] ?? {})).toEqual([
      'id',
      'probe',
      'severity',
      'title',
      'remediation',
      'docs',
      'evidence',
    ]);
  });

  it('omits remediation and docs from a finding that has neither', () => {
    const report = redact(buildReport({}, [finding()]), { enabled: true, salt: 's' });
    const parsed = JSON.parse(renderJson(report)) as { findings: Record<string, unknown>[] };
    expect(parsed.findings[0]).not.toHaveProperty('remediation');
    expect(parsed.findings[0]).not.toHaveProperty('docs');
  });

  it('is valid, parseable JSON', () => {
    const report = redact(buildReport({}, [finding()]), { enabled: true, salt: 's' });
    expect(() => {
      JSON.parse(renderJson(report)) as unknown;
    }).not.toThrow();
  });
});
