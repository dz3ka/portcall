import type { RedactedReport } from '../redact/index.ts';
import type { Finding, Severity } from '../model/finding.ts';

/**
 * Single self-contained HTML file. No external stylesheet, no font CDN, no
 * script, no image.
 *
 * The reason is not aesthetic. This report is emailed out of a customer's
 * network and opened by a security reviewer who is, correctly, suspicious of
 * it. A page that phones a CDN on open is a page that made a network call the
 * operator did not authorise, and it undoes the "nothing leaves the machine"
 * claim at the exact moment someone is checking it. A CI test asserts the
 * output loads no subresources.
 */

const SEVERITY_TEXT: Record<Severity, string> = {
  blocker: 'Blocker',
  degraded: 'Degraded',
  unknown: 'Unknown',
  ok: 'OK',
};

const VERDICT: Record<Severity, string> = {
  blocker: 'This tool will not work here until the blockers below are resolved.',
  degraded: 'This tool will work here, with the limitations below.',
  unknown: 'Some checks could not reach a conclusion.',
  ok: 'No blockers found for this profile.',
};

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Only http(s) links are rendered as links; anything else becomes plain text. */
function safeHref(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.toString();
    return undefined;
  } catch {
    return undefined;
  }
}

const STYLE = [
  ':root{--bg:#fff;--fg:#16191d;--muted:#5b6570;--line:#d9dee4;--card:#f6f8fa;',
  '--blocker:#b3261e;--degraded:#a15c00;--unknown:#4a5568;--ok:#1a7f37}',
  '@media (prefers-color-scheme:dark){:root{--bg:#0f1215;--fg:#e6e9ee;--muted:#96a0ac;',
  '--line:#2a3138;--card:#171c21;--blocker:#ff6b5e;--degraded:#e0a03a;',
  '--unknown:#9aa5b1;--ok:#4ac26b}}',
  '*{box-sizing:border-box}',
  'body{margin:0;padding:2rem 1.25rem;background:var(--bg);color:var(--fg);',
  'font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}',
  'main{max-width:60rem;margin:0 auto}',
  'h1{font-size:1.5rem;margin:0 0 .25rem}',
  'h2{font-size:1.05rem;margin:2rem 0 .75rem}',
  '.sub{color:var(--muted);margin:0 0 1.5rem}',
  '.verdict{border:1px solid var(--line);border-left-width:5px;border-radius:6px;',
  'padding:.9rem 1rem;background:var(--card);margin-bottom:1.5rem}',
  '.verdict.blocker{border-left-color:var(--blocker)}',
  '.verdict.degraded{border-left-color:var(--degraded)}',
  '.verdict.unknown{border-left-color:var(--unknown)}',
  '.verdict.ok{border-left-color:var(--ok)}',
  '.counts{color:var(--muted);font-size:.85rem;margin-top:.4rem}',
  'table{border-collapse:collapse;width:100%;font-size:.9rem}',
  'th,td{text-align:left;padding:.35rem .75rem .35rem 0;vertical-align:top}',
  'th{color:var(--muted);font-weight:500;white-space:nowrap}',
  '.finding{border:1px solid var(--line);border-radius:6px;padding:1rem;',
  'margin-bottom:.9rem;background:var(--card)}',
  '.finding h3{margin:0 0 .2rem;font-size:1rem}',
  '.badge{display:inline-block;font-size:.72rem;letter-spacing:.04em;',
  'text-transform:uppercase;padding:.12rem .45rem;border-radius:3px;',
  'border:1px solid currentColor;margin-right:.5rem}',
  '.badge.blocker{color:var(--blocker)}',
  '.badge.degraded{color:var(--degraded)}',
  '.badge.unknown{color:var(--unknown)}',
  '.badge.ok{color:var(--ok)}',
  'code,.id{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}',
  '.id{color:var(--muted)}',
  '.fix{margin-top:.6rem}',
  '.fix strong{display:block;font-size:.8rem;text-transform:uppercase;',
  'letter-spacing:.04em;color:var(--muted);margin-bottom:.15rem}',
  '.empty{border:1px dashed var(--line);border-radius:6px;padding:1.25rem;color:var(--muted)}',
  'footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);',
  'color:var(--muted);font-size:.8rem}',
  'a{color:inherit}',
  '.warn{color:var(--degraded);font-weight:600}',
].join('');

export function renderHtml(report: RedactedReport): string {
  const severity = report.summary.severity;
  const title = report.tool.name + ' report - ' + report.profile.name;

  const rows: [string, string][] = [
    ['Profile', report.profile.id + ' (' + report.profile.source + ')'],
    ['Endpoints', String(report.profile.endpoints)],
    ['Runtimes', report.profile.runtimes.join(', ')],
    ['Host', report.platform.os + '/' + report.platform.arch],
    ['Runtime', report.platform.runtime + ' ' + report.platform.runtimeVersion],
    ['Generated', report.generatedAt + ' (' + String(report.durationMs) + ' ms)'],
  ];

  const counts =
    String(report.summary.blocker) +
    ' blocker &middot; ' +
    String(report.summary.degraded) +
    ' degraded &middot; ' +
    String(report.summary.unknown) +
    ' unknown &middot; ' +
    String(report.summary.ok) +
    ' ok';

  const body = [
    '<main>',
    '<h1>' + escapeHtml(report.tool.name) + ' report</h1>',
    '<p class="sub">' +
      escapeHtml(report.profile.name) +
      ' &middot; ' +
      escapeHtml(report.tool.version) +
      '</p>',
    '<div class="verdict ' + severity + '">',
    '<div>' + escapeHtml(VERDICT[severity]) + '</div>',
    '<div class="counts">' + counts + '</div>',
    '</div>',
    '<h2>Run</h2>',
    '<table>',
    ...rows.map((row) => '<tr><th>' + escapeHtml(row[0]) + '</th><td>' + escapeHtml(row[1]) + '</td></tr>'),
    '<tr><th>Redaction</th><td>' +
      (report.redacted
        ? 'on'
        : '<span class="warn">OFF - this report may contain internal hostnames</span>') +
      '</td></tr>',
    '</table>',
    '<h2>Findings</h2>',
    report.findings.length === 0
      ? '<p class="empty">No findings. This build registers no probes yet (M0); an empty ' +
        'report means the run completed, not that the network was checked.</p>'
      : report.findings.map(renderFinding).join('\n'),
    '<footer>',
    'Generated by ' +
      escapeHtml(report.tool.name) +
      ' ' +
      escapeHtml(report.tool.version) +
      '. No data left this machine to produce this file, and this file loads ' +
      'nothing when opened.',
    '</footer>',
    '</main>',
  ].join('\n');

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="robots" content="noindex, nofollow">',
    '<title>' + escapeHtml(title) + '</title>',
    '<style>' + STYLE + '</style>',
    '</head>',
    '<body>',
    body,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

function renderFinding(finding: Finding): string {
  const parts: string[] = [
    '<article class="finding">',
    '<h3><span class="badge ' +
      finding.severity +
      '">' +
      escapeHtml(SEVERITY_TEXT[finding.severity]) +
      '</span>' +
      escapeHtml(finding.title) +
      '</h3>',
    '<div class="id">' + escapeHtml(finding.id) + '</div>',
  ];

  if (finding.evidence.length > 0) {
    parts.push('<table>');
    for (const evidence of finding.evidence) {
      parts.push(
        '<tr><th>' +
          escapeHtml(evidence.label) +
          '</th><td><code>' +
          escapeHtml(evidence.value) +
          '</code></td></tr>',
      );
    }
    parts.push('</table>');
  }

  if (finding.remediation !== undefined) {
    parts.push('<div class="fix"><strong>Fix</strong>' + escapeHtml(finding.remediation) + '</div>');
  }

  if (finding.docs !== undefined) {
    const href = safeHref(finding.docs);
    parts.push(
      href === undefined
        ? '<div class="fix"><strong>Docs</strong>' + escapeHtml(finding.docs) + '</div>'
        : '<div class="fix"><strong>Docs</strong><a href="' +
            escapeHtml(href) +
            '" rel="noreferrer noopener">' +
            escapeHtml(finding.docs) +
            '</a></div>',
    );
  }

  parts.push('</article>');
  return parts.join('\n');
}
