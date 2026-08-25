import { describe, expect, it } from 'vitest';
import { renderText } from '../src/report/text.ts';
import { redact } from '../src/redact/index.ts';
import { buildReport, finding } from './helpers/report-fixture.ts';

describe('renderText', () => {
  it('includes the tool name, version and profile name in the header', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    const text = renderText(report);
    expect(text).toContain('portcall 0.1.0');
    expect(text).toContain('Fixture profile');
  });

  it('renders a no-findings message when there are none', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    const text = renderText(report);
    expect(text).toContain('No findings.');
  });

  it('renders each finding with id, title and evidence', () => {
    const report = redact(
      buildReport({}, [
        finding({
          id: 'tls.intercepted',
          severity: 'blocker',
          title: 'TLS traffic is being intercepted',
          evidence: [{ label: 'root CA', value: 'Acme Corp Proxy CA', kind: 'text' }],
          remediation: 'Set NODE_EXTRA_CA_CERTS',
        }),
      ]),
      { enabled: true, salt: 's' },
    );
    const text = renderText(report);
    expect(text).toContain('tls.intercepted');
    expect(text).toContain('TLS traffic is being intercepted');
    expect(text).toContain('root CA: Acme Corp Proxy CA');
    expect(text).toContain('Fix:');
    expect(text).toContain('Set NODE_EXTRA_CA_CERTS');
  });

  it('renders docs when present', () => {
    const report = redact(
      buildReport({}, [finding({ docs: 'https://example.com/docs/tls' })]),
      { enabled: true, salt: 's' },
    );
    expect(renderText(report)).toContain('Docs: https://example.com/docs/tls');
  });

  it('shows the summary counts and the severity verdict', () => {
    const report = redact(
      buildReport({}, [finding({ severity: 'blocker', remediation: 'fix' })]),
      { enabled: true, salt: 's' },
    );
    const text = renderText(report);
    expect(text).toContain('1 blocker, 0 degraded, 0 unknown, 0 ok');
    expect(text).toContain('This tool will not work here until the blockers below are resolved.');
  });

  it('warns plainly when redaction is off', () => {
    const report = redact(buildReport(), { enabled: false, salt: 's' });
    expect(renderText(report)).toContain('redaction  OFF - this report may contain internal hostnames');
  });

  it('shows redaction on when enabled', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    expect(renderText(report)).toContain('redaction  on');
  });

  it('contains no ANSI escape codes (plain ASCII for locked-down machines)', () => {
    const report = redact(
      buildReport({}, [finding({ severity: 'blocker', remediation: 'fix it' })]),
      { enabled: true, salt: 's' },
    );
    // eslint-disable-next-line no-control-regex
    expect(renderText(report)).not.toMatch(/\x1b\[/);
  });
});
