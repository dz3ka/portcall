import type { RedactedReport } from '../redact/index.ts';
import type { Finding } from '../model/finding.ts';

/**
 * The canonical renderer. The HTML and text views are derived from exactly
 * this object, so anything true of the JSON is true of the other two.
 *
 * Keys are written in a fixed order rather than left to object-literal
 * ordering, because customers diff these reports across runs and a reordered
 * key is noise that looks like a change.
 */
export function renderJson(report: RedactedReport): string {
  const canonical = {
    schemaVersion: report.schemaVersion,
    tool: { name: report.tool.name, version: report.tool.version },
    generatedAt: report.generatedAt,
    durationMs: report.durationMs,
    redacted: report.redacted,
    platform: {
      os: report.platform.os,
      arch: report.platform.arch,
      runtime: report.platform.runtime,
      runtimeVersion: report.platform.runtimeVersion,
    },
    profile: {
      id: report.profile.id,
      name: report.profile.name,
      source: report.profile.source,
      endpoints: report.profile.endpoints,
      runtimes: report.profile.runtimes,
    },
    summary: {
      severity: report.summary.severity,
      total: report.summary.total,
      blocker: report.summary.blocker,
      degraded: report.summary.degraded,
      unknown: report.summary.unknown,
      ok: report.summary.ok,
    },
    findings: report.findings.map(canonicalFinding),
  };
  return JSON.stringify(canonical, null, 2);
}

function canonicalFinding(finding: Finding): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: finding.id,
    probe: finding.probe,
    severity: finding.severity,
    title: finding.title,
  };
  if (finding.remediation !== undefined) out['remediation'] = finding.remediation;
  if (finding.docs !== undefined) out['docs'] = finding.docs;
  out['evidence'] = finding.evidence.map((item) => ({
    label: item.label,
    kind: item.kind,
    value: item.value,
  }));
  return out;
}
