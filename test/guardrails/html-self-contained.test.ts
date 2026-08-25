import { describe, expect, it } from 'vitest';
import { renderHtml } from '../../src/report/html.ts';
import { redact } from '../../src/redact/index.ts';
import { buildReport, finding } from '../helpers/report-fixture.ts';

/**
 * SPEC.md 6: the HTML report is a single self-contained file, opened by a
 * suspicious security reviewer after leaving a customer network. It must load
 * no subresource: no external script, stylesheet, image or font, and no
 * `http`-scheme URL except inside an `<a href="...">` (a docs link the reader
 * chooses to click, not something the page fetches on open).
 */
describe('html self-contained guardrail', () => {
  // Evidence and remediation are rendered as inert escaped text (see
  // src/report/html.ts renderFinding), never turned into links — only `docs`
  // becomes an <a href>. So this fixture keeps the only http(s) URL in `docs`,
  // matching how a real probe would use the fields.
  it('renders no src=, <script, <link, url(, or @import, and only http(s) URLs inside <a href>', () => {
    const report = redact(
      buildReport({}, [
        finding({
          title: 'Reachability check',
          evidence: [{ label: 'endpoint', value: 'api.example.com', kind: 'hostname' }],
          docs: 'https://example.com/docs/finding',
          remediation: 'point NODE_EXTRA_CA_CERTS at the corporate root and re-run',
        }),
      ]),
      { enabled: true, salt: 'fixed-salt' },
    );
    const html = renderHtml(report);

    expect(html).not.toContain('src=');
    expect(html).not.toContain('<script');
    expect(html).not.toContain('<link');
    expect(html).not.toContain('url(');
    expect(html).not.toContain('@import');

    // Every http(s)-scheme URL in the document must appear inside an <a href="...">.
    const hrefUrls = new Set<string>();
    for (const match of html.matchAll(/<a\s+href="(https?:\/\/[^"]*)"/g)) {
      const url = match[1];
      if (url !== undefined) hrefUrls.add(url);
    }
    const allUrls = html.match(/https?:\/\/[^\s"'<>]+/g) ?? [];
    for (const url of allUrls) {
      // Strip a trailing '"' that a non-href occurrence might carry from evidence text.
      const bare = url.replace(/["']+$/, '');
      expect(hrefUrls.has(bare) || hrefUrls.has(url)).toBe(true);
    }
  });

  it('emits no http(s) URL at all when the report has no docs links', () => {
    const report = redact(buildReport({}, [finding()]), { enabled: true, salt: 'fixed-salt' });
    const html = renderHtml(report);
    expect(html.match(/https?:\/\//g)).toBeNull();
  });
});
