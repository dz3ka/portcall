import type { Finding, Severity } from './finding.ts';

/** Bumped when the JSON shape changes incompatibly. Consumers pin on this. */
export const REPORT_SCHEMA_VERSION = 1;

export interface ReportSummary {
  total: number;
  blocker: number;
  degraded: number;
  unknown: number;
  ok: number;
  /** Roll-up of the worst finding. Drives the process exit code (ADR-0006). */
  severity: Severity;
}

export interface ReportPlatform {
  /** `darwin` | `linux` | `win32`. Coarse on purpose — not a fingerprint. */
  os: string;
  arch: string;
  /** `bun` or `node`. The trust-store answer differs per runtime. */
  runtime: string;
  runtimeVersion: string;
}

export interface ReportProfile {
  name: string;
  /** Profile identifier as given on the command line. */
  id: string;
  /** `builtin` or `file` — never an absolute path, which would leak a username. */
  source: 'builtin' | 'file';
  endpoints: number;
  runtimes: string[];
}

/**
 * The canonical report. JSON is the source of truth; the HTML and text
 * renderers are views over exactly this object and never reach past it for
 * extra data (see ADR-0005 — that is what makes redaction a single boundary).
 */
export interface Report {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  tool: { name: string; version: string };
  generatedAt: string;
  durationMs: number;
  platform: ReportPlatform;
  profile: ReportProfile;
  /** False only when the operator passed `--no-redact`. */
  redacted: boolean;
  summary: ReportSummary;
  findings: Finding[];
}
