import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderHtml, escapeHtml } from '../src/report/html.ts';
import { renderJson } from '../src/report/json.ts';
import { redact } from '../src/redact/index.ts';
import { buildReport, finding, goldenReport } from './helpers/report-fixture.ts';

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

/**
 * The golden report (`test/fixtures/report/golden-report.json`): one finding
 * per severity, evidence covering every `EvidenceKind`, redacted with a fixed
 * salt. The fixture is the *rendered JSON* of that report, so it pins the whole
 * document — `REPORT_SCHEMA_VERSION` is public API and report-json.test.ts pins
 * key order but never the bytes around it — and the same in-memory report is
 * what the tests below render to HTML.
 *
 * There is deliberately no committed golden HTML and no `UPDATE_GOLDEN` mode. A
 * golden that regenerates itself on a red run catches nothing; regenerate this
 * one on purpose, then read the diff before committing it:
 *
 *   node --input-type=module -e "import {writeFileSync} from 'node:fs'; import {goldenReport} from './test/helpers/report-fixture.ts'; import {redact} from './src/redact/index.ts'; import {renderJson} from './src/report/json.ts'; writeFileSync('test/fixtures/report/golden-report.json', renderJson(redact(goldenReport(), {enabled: true, salt: 'fixed-salt'})) + '\n')"
 *
 * Line endings: the fixture is compared newline-agnostically (CRLF folded to
 * LF, trailing whitespace trimmed on both sides). The repo has no
 * `.gitattributes`, so a Windows checkout under `core.autocrlf=true` rewrites
 * the committed file and would otherwise redden `verify` on line endings alone.
 * No value in the report contains a newline, so folding cannot mask a real
 * difference.
 */
const GOLDEN_PATH = join(import.meta.dirname, 'fixtures', 'report', 'golden-report.json');

function normaliseNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n').trimEnd();
}

describe('the golden report', () => {
  const redacted = redact(goldenReport(), { enabled: true, salt: 'fixed-salt' });

  it('renders JSON byte for byte identical to the committed fixture', () => {
    const golden = readFileSync(GOLDEN_PATH, 'utf8');
    expect(normaliseNewlines(renderJson(redacted))).toBe(normaliseNewlines(golden));
  });

  it('names every severity in the HTML render', () => {
    const html = renderHtml(redacted);
    expect(html).toContain('<span class="badge blocker">Blocker</span>');
    expect(html).toContain('<span class="badge degraded">Degraded</span>');
    expect(html).toContain('<span class="badge unknown">Unknown</span>');
    expect(html).toContain('<span class="badge ok">OK</span>');
  });

  it('carries every evidence value the JSON carries into the HTML render', () => {
    const html = renderHtml(redacted);
    for (const item of redacted.findings) {
      for (const evidence of item.evidence) {
        expect(html).toContain(escapeHtml(evidence.value));
      }
    }
  });

  it('leaks no pre-redaction identifier into the HTML render', () => {
    const html = renderHtml(redacted);
    for (const value of [
      'api.internal.example',
      '10.31.0.9',
      'Acme Corp',
      'wpad.internal.example',
      '04:9e:2b:11',
      '/etc/ssl/certs',
      'svc-buildbot',
    ]) {
      expect(html).not.toContain(value);
    }
  });
});
