import { arch, platform } from 'node:process';
import type { Finding } from '../model/finding.ts';
import { assertRemediable } from '../model/finding.ts';
import type { Report } from '../model/report.ts';
import { REPORT_SCHEMA_VERSION } from '../model/report.ts';
import type { LoadedProfile } from '../profiles/schema.ts';
import { NetworkGuard } from '../net/guard.ts';
import { probeErrorFinding } from './probe-error.ts';
import { summarise, sortFindings } from './rollup.ts';
import { TOOL_NAME, VERSION } from '../version.ts';
import { PROBES } from './registry.ts';

/**
 * A trust anchor the `tls` probe saw terminating a chain it did not judge
 * public (ADR-0034).
 *
 * Declared here, beside `ProbeContext`, because both probes need the type and
 * `engine/` may not gain an edge into `probes/`. The unions are spelled inline
 * rather than importing `RootClass`, for the same reason.
 */
export interface ObservedAnchor {
  /** DER of the anchor the peer actually presented, or null when it presented none. */
  der: Uint8Array | null;
  /** Canonical issuer DN of the chain terminus - the only identity available when `der` is null. */
  canonicalIssuer: string;
  /** Canonical subject DN of the terminus, for the human-facing evidence line. */
  canonicalSubject: string;
  host: string;
  /** Same vocabulary as `CapturedChain.via` and the `connection` evidence label. */
  via: 'direct' | 'proxy';
  anchorClass: 'private' | 'indeterminate';
}

export interface ProbeContext {
  profile: LoadedProfile;
  net: NetworkGuard;
  /** Absolute deadline for the whole run, as `Date.now()` milliseconds. */
  deadline: number;
  signal: AbortSignal;
  /**
   * Appended to by `tls`, read by `truststore`. One array per run, shared by
   * every context - `run()` builds it above the probe loop, not in the object
   * literal inside it, or each probe would get its own empty copy.
   */
  observedAnchors: ObservedAnchor[];
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
  // One array for the whole run: `tls` pushes what it saw, `truststore` reads
  // it. Built here rather than in the per-probe literal below, which would
  // discard every observation between probes.
  const observedAnchors: ObservedAnchor[] = [];
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
        observedAnchors,
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
    return [probeErrorFinding(probe.name, error)];
  }
}
