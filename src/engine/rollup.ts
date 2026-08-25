import type { Finding, Severity } from '../model/finding.ts';
import { severityRank } from '../model/finding.ts';
import type { ReportSummary } from '../model/report.ts';

/**
 * Roll a set of findings up to one severity.
 *
 * An empty run is `ok`: nothing was checked, so nothing failed. That is the M0
 * state and it is deliberately not `unknown` — `unknown` means a check ran and
 * could not decide, which is a different and more alarming statement.
 */
export function rollUp(findings: readonly Finding[]): Severity {
  let worst: Severity = 'ok';
  for (const finding of findings) {
    if (severityRank(finding.severity) < severityRank(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}

export function summarise(findings: readonly Finding[]): ReportSummary {
  const counts = { blocker: 0, degraded: 0, unknown: 0, ok: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return {
    total: findings.length,
    blocker: counts.blocker,
    degraded: counts.degraded,
    unknown: counts.unknown,
    ok: counts.ok,
    severity: rollUp(findings),
  };
}

/** Worst-first, then by probe, then by id, so report diffs are meaningful. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byProbe = a.probe.localeCompare(b.probe);
    if (byProbe !== 0) return byProbe;
    return a.id.localeCompare(b.id);
  });
}
