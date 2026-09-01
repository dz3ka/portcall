import type { RedactedReport } from '../redact/index.ts';
import type { Severity } from '../model/finding.ts';

/**
 * Human output for the terminal. Plain ASCII and no colour: this runs on a
 * stranger's locked-down machine, piped into a ticket as often as it is read
 * on screen, and a report full of escape codes is a report nobody pastes.
 */

const SEVERITY_LABEL: Record<Severity, string> = {
  blocker: 'BLOCKER ',
  degraded: 'DEGRADED',
  unknown: 'UNKNOWN ',
  ok: 'OK      ',
};

const VERDICT: Record<Severity, string> = {
  blocker: 'This tool will not work here until the blockers below are resolved.',
  degraded: 'This tool will work here, with the limitations below.',
  unknown: 'Some checks could not reach a conclusion. See below.',
  ok: 'No blockers found for this profile.',
};

export function renderText(report: RedactedReport): string {
  const lines: string[] = [];
  const rule = '-'.repeat(72);

  lines.push(`${report.tool.name} ${report.tool.version}  -  ${report.profile.name}`);
  lines.push(rule);
  lines.push(`profile    ${report.profile.id} (${report.profile.source})`);
  lines.push(`endpoints  ${String(report.profile.endpoints)}`);
  lines.push(`runtimes   ${report.profile.runtimes.join(', ')}`);
  lines.push(
    `host       ${report.platform.os}/${report.platform.arch}` +
      `  ${report.platform.runtime} ${report.platform.runtimeVersion}`,
  );
  lines.push(`generated  ${report.generatedAt} (${String(report.durationMs)} ms)`);
  lines.push(
    `redaction  ${report.redacted ? 'on' : 'OFF - this report may contain internal hostnames'}`,
  );
  lines.push(rule);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('No findings.');
    lines.push('');
    lines.push(
      'Every check the active profile asked for ran and reported nothing.',
    );
    lines.push(
      'Portcall probes only the hosts that profile names, on port 443 only, so',
    );
    lines.push(
      'this is a clean result for that profile - not a clean bill of health for',
    );
    lines.push('the network.');
  } else {
    for (const finding of report.findings) {
      lines.push(`[${SEVERITY_LABEL[finding.severity]}] ${finding.id}`);
      lines.push(`  ${finding.title}`);
      for (const evidence of finding.evidence) {
        lines.push(`    ${evidence.label}: ${evidence.value}`);
      }
      if (finding.remediation !== undefined) {
        lines.push('  Fix:');
        for (const line of wrap(finding.remediation, 66)) lines.push(`    ${line}`);
      }
      if (finding.docs !== undefined) lines.push(`  Docs: ${finding.docs}`);
      lines.push('');
    }
  }

  lines.push(rule);
  lines.push(
    `${String(report.summary.blocker)} blocker, ${String(report.summary.degraded)} degraded, ` +
      `${String(report.summary.unknown)} unknown, ${String(report.summary.ok)} ok`,
  );
  lines.push(VERDICT[report.summary.severity]);
  lines.push('');

  return lines.join('\n');
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/).filter((word) => word.length > 0);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);
  return lines;
}
