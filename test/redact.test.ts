import { describe, expect, it } from 'vitest';
import { redact } from '../src/redact/index.ts';
import { buildReport, finding } from './helpers/report-fixture.ts';
import type { Evidence, EvidenceKind } from '../src/model/finding.ts';

const SALT_A = 'fixed-salt-a';
const SALT_B = 'fixed-salt-b';

function evidence(kind: EvidenceKind, value: string, label = kind): Evidence {
  return { label, value, kind };
}

describe('redact', () => {
  it.each<EvidenceKind>(['hostname', 'ip', 'username', 'serial', 'path', 'url', 'dn'])(
    'hashes sensitive kind %s into a tagged token',
    (kind) => {
      const report = buildReport({}, [finding({ evidence: [evidence(kind, 'super-secret-value')] })]);
      const redacted = redact(report, { enabled: true, salt: SALT_A });
      const value = redacted.findings[0]?.evidence[0]?.value;
      expect(value).toBeDefined();
      expect(value).not.toBe('super-secret-value');
      expect(value).toMatch(/^<[a-z]+:[0-9a-f]{12}>$/);
    },
  );

  it.each<EvidenceKind>(['public', 'text', 'number'])(
    'never hashes non-sensitive kind %s',
    (kind) => {
      const report = buildReport({}, [finding({ evidence: [evidence(kind, 'plain-value')] })]);
      const redacted = redact(report, { enabled: true, salt: SALT_A });
      expect(redacted.findings[0]?.evidence[0]?.value).toBe('plain-value');
    },
  );

  it('keeps profile-declared hosts in cleartext (publicValues)', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', 'api.anthropic.com')] })]);
    const redacted = redact(report, {
      enabled: true,
      salt: SALT_A,
      publicValues: ['api.anthropic.com'],
    });
    expect(redacted.findings[0]?.evidence[0]?.value).toBe('api.anthropic.com');
  });

  it('publicValues comparison is case-insensitive and trims whitespace', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', ' API.Anthropic.com ')] })]);
    const redacted = redact(report, {
      enabled: true,
      salt: SALT_A,
      publicValues: ['api.anthropic.com'],
    });
    expect(redacted.findings[0]?.evidence[0]?.value).toBe(' API.Anthropic.com ');
  });

  it('a sensitive value not in publicValues is still hashed', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', 'internal.corp.local')] })]);
    const redacted = redact(report, {
      enabled: true,
      salt: SALT_A,
      publicValues: ['api.anthropic.com'],
    });
    expect(redacted.findings[0]?.evidence[0]?.value).not.toBe('internal.corp.local');
  });

  it('enabled:false passes evidence through unredacted and sets redacted:false', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', 'internal.corp.local')] })]);
    const redacted = redact(report, { enabled: false, salt: SALT_A });
    expect(redacted.redacted).toBe(false);
    expect(redacted.findings[0]?.evidence[0]?.value).toBe('internal.corp.local');
  });

  it('enabled:true sets redacted:true on the report', () => {
    const report = buildReport({}, [finding()]);
    const redacted = redact(report, { enabled: true, salt: SALT_A });
    expect(redacted.redacted).toBe(true);
  });

  it('same value produces the same token within one report (one salt)', () => {
    const report = buildReport({}, [
      finding({ id: 'a', evidence: [evidence('hostname', 'repeat.internal')] }),
      finding({ id: 'b', probe: 'other', evidence: [evidence('hostname', 'repeat.internal')] }),
    ]);
    const redacted = redact(report, { enabled: true, salt: SALT_A });
    const tokenA = redacted.findings.find((f) => f.id === 'a')?.evidence[0]?.value;
    const tokenB = redacted.findings.find((f) => f.id === 'b')?.evidence[0]?.value;
    expect(tokenA).toBeDefined();
    expect(tokenA).toBe(tokenB);
  });

  it('different salts produce different tokens across reports for the same value', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', 'repeat.internal')] })]);
    const redactedA = redact(report, { enabled: true, salt: SALT_A });
    const redactedB = redact(report, { enabled: true, salt: SALT_B });
    const tokenA = redactedA.findings[0]?.evidence[0]?.value;
    const tokenB = redactedB.findings[0]?.evidence[0]?.value;
    expect(tokenA).toBeDefined();
    expect(tokenA).not.toBe(tokenB);
  });

  it('generates a fresh random salt when none is provided, so two default runs differ', () => {
    const report = buildReport({}, [finding({ evidence: [evidence('hostname', 'repeat.internal')] })]);
    const redactedA = redact(report, { enabled: true });
    const redactedB = redact(report, { enabled: true });
    expect(redactedA.findings[0]?.evidence[0]?.value).not.toBe(redactedB.findings[0]?.evidence[0]?.value);
  });

  it('preserves remediation and docs fields', () => {
    const report = buildReport({}, [
      finding({ remediation: 'do the thing', docs: 'https://example.com/docs' }),
    ]);
    const redacted = redact(report, { enabled: true, salt: SALT_A });
    expect(redacted.findings[0]?.remediation).toBe('do the thing');
    expect(redacted.findings[0]?.docs).toBe('https://example.com/docs');
  });
});
