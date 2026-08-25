import { arch, platform } from 'node:process';
import type { Finding } from '../model/finding.ts';
import { assertRemediable } from '../model/finding.ts';
import type { Report } from '../model/report.ts';
import { REPORT_SCHEMA_VERSION } from '../model/report.ts';
import type { LoadedProfile } from '../profiles/schema.ts';
import { NetworkGuard } from '../net/guard.ts';
import { summarise, sortFindings } from './rollup.ts';
import { TOOL_NAME, VERSION } from '../version.ts';
import { PROBES } from './registry.ts';

export interface ProbeContext {
  profile: LoadedProfile;
  net: NetworkGuard;
  /** Absolute deadline for the whole run, as `Date.now()` milliseconds. */
  deadline: number;
  signal: AbortSignal;
}

/**
 * A probe. I/O lives inside `run`, at the edge; the evaluation logic each probe
 * delegates to is a pure function of `(profile, environment) => Finding[]` so
 * it can be tested against recorded fixtures (SPEC.md 6).
 */
export interface Probe {
  name: string;
  run(context: ProbeContext): Promise<Finding[]>;
}

export interface RunOptions {
  profile: LoadedProfile;
  /** Global budget for the whole run, in milliseconds. */
  timeoutMs: number;
  now?: () => Date;
}

export interface RunResult {
  report: Report;
  /** Hosts the run was permitted to contact, for the report footer. */
  net: NetworkGuard;
}

function runtimeInfo(): { runtime: string; runtimeVersion: string } {
  const bun = (globalThis as { Bun?: { version: string } }).Bun;
  if (bun !== undefined) return { runtime: 'bun', runtimeVersion: bun.version };
  return { runtime: 'node', runtimeVersion: process.versions.node };
}

/**
 * Run every registered probe under one global timeout budget.
 *
 * A probe that throws does not fail the run: this tool exists to be run once,
 * on a stranger's laptop, and returning four findings plus one honest
 * `probe errored` is far more useful than returning nothing. The error becomes
 * an `unknown` finding, which rolls up to a non-zero exit so it cannot be
 * mistaken for a pass.
 */
export async function run(options: RunOptions): Promise<RunResult> {
  const startedAt = Date.now();
  const now = options.now ?? (() => new Date());
  const generatedAt = now().toISOString();

  const net = new NetworkGuard(options.profile.profile);
  const controller = new AbortController();
  const deadline = startedAt + options.timeoutMs;
  const timer = setTimeout(() => {
    controller.abort();
  }, options.timeoutMs);
  // Do not hold the event loop open just for the budget timer.
  timer.unref?.();

  const findings: Finding[] = [];
  try {
    for (const probe of PROBES) {
      const context: ProbeContext = {
        profile: options.profile,
        net,
        deadline,
        signal: controller.signal,
      };
      findings.push(...(await runProbe(probe, context)));
    }
  } finally {
    clearTimeout(timer);
  }

  for (const finding of findings) assertRemediable(finding);

  const sorted = sortFindings(findings);
  const { runtime, runtimeVersion } = runtimeInfo();

  const report: Report = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: VERSION },
    generatedAt,
    durationMs: Date.now() - startedAt,
    platform: { os: platform, arch, runtime, runtimeVersion },
    profile: {
      name: options.profile.profile.name,
      id: options.profile.id,
      source: options.profile.source,
      endpoints: options.profile.profile.endpoints.length,
      runtimes: [...options.profile.profile.runtimes],
    },
    redacted: false, // set at the redaction boundary, which every report passes through
    summary: summarise(sorted),
    findings: sorted,
  };

  return { report, net };
}

async function runProbe(probe: Probe, context: ProbeContext): Promise<Finding[]> {
  try {
    return await probe.run(context);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return [
      {
        id: `${probe.name}.probe-error`,
        probe: probe.name,
        severity: 'unknown',
        title: `The ${probe.name} probe could not complete`,
        evidence: [{ label: 'error', value: reason, kind: 'text' }],
        remediation:
          `Re-run with --timeout raised, and send this report to the tool vendor. ` +
          `Other probes in this run are unaffected; only ${probe.name} results are missing.`,
      },
    ];
  }
}
