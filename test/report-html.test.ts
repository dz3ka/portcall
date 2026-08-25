import { describe, expect, it } from 'vitest';
import { renderHtml, escapeHtml } from '../src/report/html.ts';
import { redact } from '../src/redact/index.ts';
import { buildReport, finding } from './helpers/report-fixture.ts';

describe('escapeHtml', () => {
  it('escapes all five special characters', () => {
    expect(escapeHtml(`<script>&"'</script>`)).toBe(
      '&lt;script&gt;&amp;&quot;&#39;&lt;/script&gt;',
    );
  });
});

describe('renderHtml', () => {
  it('escapes a <script> tag appearing in a finding title so it cannot execute', () => {
    const report = redact(
      buildReport({}, [finding({ title: '<script>alert(1)</script>' })]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('escapes a <script> tag appearing in evidence value', () => {
    const report = redact(
      buildReport({}, [
        finding({ evidence: [{ label: 'payload', value: '<script>alert(2)</script>', kind: 'text' }] }),
      ]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).not.toContain('<script>alert(2)</script>');
    expect(html).toContain('&lt;script&gt;alert(2)&lt;/script&gt;');
  });

  it('escapes a <script> tag in the profile name (report title/header)', () => {
    const report = redact(buildReport({ profile: { ...buildReport().profile, name: '<script>x</script>' } }), {
      enabled: true,
      salt: 's',
    });
    const html = renderHtml(report);
    expect(html).not.toContain('<script>x</script>');
  });

  it('escapes a <script> tag in remediation text', () => {
    const report = redact(
      buildReport({}, [finding({ remediation: '<script>alert(3)</script>' })]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).not.toContain('<script>alert(3)</script>');
  });

  it('only renders docs as a link when it is a real http(s) URL', () => {
    const report = redact(
      buildReport({}, [finding({ docs: 'javascript:alert(1)' })]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).not.toContain('href="javascript:alert(1)"');
  });

  it('renders a valid https docs URL as an anchor', () => {
    const report = redact(
      buildReport({}, [finding({ docs: 'https://example.com/docs/tls' })]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).toContain('href="https://example.com/docs/tls"');
  });

  it('is well-formed enough to start with <!doctype html> and end with </html>', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    const html = renderHtml(report).trim();
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html.endsWith('</html>')).toBe(true);
  });

  it('shows the no-probes-yet message when there are no findings', () => {
    const report = redact(buildReport(), { enabled: true, salt: 's' });
    expect(renderHtml(report)).toContain('No findings.');
  });

  it('has no external subresource references (self-contained)', () => {
    const report = redact(
      buildReport({}, [finding({ docs: 'https://example.com/docs' })]),
      { enabled: true, salt: 's' },
    );
    const html = renderHtml(report);
    expect(html).not.toContain('src=');
    expect(html).not.toContain('<link');
    expect(html).not.toContain('url(');
    expect(html).not.toContain('@import');
  });
});
