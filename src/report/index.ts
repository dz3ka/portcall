import type { RedactedReport } from '../redact/index.ts';
import { renderJson } from './json.ts';
import { renderHtml } from './html.ts';
import { renderText } from './text.ts';

export const FORMATS = ['json', 'html', 'text'] as const;
export type Format = (typeof FORMATS)[number];

export function isFormat(value: string): value is Format {
  return (FORMATS as readonly string[]).includes(value);
}

/**
 * Renderers accept only a `RedactedReport`, so every path to output runs
 * through `redact()` first (ADR-0005).
 */
export function render(report: RedactedReport, format: Format): string {
  switch (format) {
    case 'json':
      return renderJson(report);
    case 'html':
      return renderHtml(report);
    case 'text':
      return renderText(report);
  }
}

export { renderJson, renderHtml, renderText };
