import { describe, expect, it } from 'vitest';
import { renderHtml } from '../../src/report/html.ts';
import { redact } from '../../src/redact/index.ts';
import { buildReport, finding, goldenReport } from '../helpers/report-fixture.ts';

/**
 * SPEC.md 6: the HTML report is a single self-contained file, opened by a
 * suspicious security reviewer after leaving a customer network. It must load
 * no subresource: no external script, stylesheet, image or font, and no
 * `http`-scheme URL except inside an `<a href="...">` (a docs link the reader
 * chooses to click, not something the page fetches on open).
 *
 * What this proves, exactly: the emitted string contains none of the
 * fetch-triggering constructs enumerated below, and every absolute URL in it
 * sits inside an anchor. It is a *static tripwire on a fixed template*, not a
 * load check — nothing here opens the document, so a construct absent from the
 * list would pass unnoticed. That is sound only because `src/report/html.ts` is
 * hand-written string concatenation whose whole tag vocabulary a reviewer can
 * read in one sitting; it would not survive templating the renderer, and the
 * tripwire would have to become a real load check if it ever did (ADR-0045).
 */

/** The enumerated constructs, applied to every document the tests below render. */
function assertSelfContained(html: string): void {
  expect(html).not.toContain('src=');
  expect(html).not.toContain('<script');
  expect(html).not.toContain('<link');
  expect(html).not.toContain('url(');
  expect(html).not.toContain('@import');

  // Constructs the URL rule below cannot see: an embedded document fetches
  // through its own attribute, `srcset=` carries a URL list that `src=` does
  // not match, and a meta refresh navigates on open with no URL-bearing
  // attribute at all when the target is relative.
  expect(html).not.toContain('<iframe');
  expect(html).not.toContain('<object');
  expect(html).not.toContain('<embed');
  expect(html).not.toContain('srcset=');
  expect(html.toLowerCase()).not.toMatch(/http-equiv\s*=\s*["']?refresh/);

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
}

describe('html self-contained guardrail', () => {
  // Evidence and remediation are rendered as inert escaped text (see
  // src/report/html.ts renderFinding), never turned into links — only `docs`
  // becomes an <a href>. So this fixture keeps the only http(s) URL in `docs`,
  // matching how a real probe would use the fields.
  it('renders none of the enumerated fetch-triggering constructs, and only http(s) URLs inside <a href>', () => {
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

    assertSelfContained(renderHtml(report));
  });

  // The golden report is the widest document the renderer produces here: one
  // finding per severity and one piece of evidence per `EvidenceKind`, so every
  // branch of `renderFinding` — badge, evidence table, fix block, docs anchor —
  // is on the page the scan runs over.
  it('renders none of them for the golden report either, which exercises every severity and evidence kind', () => {
    const report = redact(goldenReport(), { enabled: true, salt: 'fixed-salt' });

    assertSelfContained(renderHtml(report));
  });

  it('emits no http(s) URL at all when the report has no docs links', () => {
    const report = redact(buildReport({}, [finding()]), { enabled: true, salt: 'fixed-salt' });
    const html = renderHtml(report);
    expect(html.match(/https?:\/\//g)).toBeNull();
  });
});
