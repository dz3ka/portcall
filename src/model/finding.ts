/**
 * The finding model (SPEC.md §6).
 *
 * A `Finding` is the only thing a probe may produce. Probes are pure functions
 * of `(profile, environment) => Finding[]`, so this type is the contract
 * between the I/O edges and the fixture-testable evaluation logic.
 */

export type Severity = 'blocker' | 'degraded' | 'ok' | 'unknown';

/**
 * Severity ordered worst-first. Used for roll-up and for report ordering, so
 * that the thing that blocks the deployment is the first thing a reader sees.
 */
export const SEVERITY_ORDER: readonly Severity[] = ['blocker', 'degraded', 'unknown', 'ok'];

export function severityRank(severity: Severity): number {
  const rank = SEVERITY_ORDER.indexOf(severity);
  /* c8 ignore next */
  return rank === -1 ? SEVERITY_ORDER.length : rank;
}

/**
 * What kind of value a piece of evidence holds.
 *
 * This exists so redaction is a decision about *data classification*, not a
 * regex sweep over free text at the report boundary. A probe declares what it
 * observed; `redact/` decides what is safe to emit. A probe cannot opt out.
 *
 * - `hostname` / `ip` / `username` / `serial` / `path` / `url` / `dn` are
 *   potentially customer-identifying and are hashed unless redaction is off.
 * - `dn` is an X.509 distinguished name (a certificate subject or issuer). It
 *   is its own kind because a private CA's DN routinely carries the customer's
 *   own organisation name - `CN=Acme Corp Internal Root, O=Acme Corp` - which
 *   is exactly the string a report must not leak. A *public* CA's name is
 *   already public knowledge and is emitted as `public` instead.
 * - `public` is a value the vendor already knows (an endpoint named in the
 *   active profile, a public CA name) and is emitted verbatim.
 * - `text` / `number` are probe-authored descriptions with no customer data in
 *   them. Probes must not smuggle identifiers in here; the guardrail for that
 *   is code review plus the rule that identifiers have their own kinds.
 */
export type EvidenceKind =
  | 'hostname'
  | 'ip'
  | 'username'
  | 'serial'
  | 'path'
  | 'url'
  | 'dn'
  | 'public'
  | 'text'
  | 'number';

export interface Evidence {
  /** Short human label, e.g. `resolved address`. Never contains customer data. */
  label: string;
  /** The observed value. Redacted at the report boundary according to `kind`. */
  value: string;
  kind: EvidenceKind;
}

export interface Finding {
  /**
   * Stable, greppable identifier, e.g. `tls.intercepted`. Once public this is
   * API: customers grep for it in their own CI. Renaming one is a breaking
   * change.
   */
  id: string;
  /** Probe that produced the finding, e.g. `tls`. */
  probe: string;
  severity: Severity;
  /** One line, imperative, no customer data. */
  title: string;
  evidence: Evidence[];
  /**
   * What to change. Optional in the type only because `ok` findings have
   * nothing to remediate; `assertRemediable` enforces the real rule.
   */
  remediation?: string;
  /** Link to the long-form explanation in the repo. */
  docs?: string;
}

/**
 * CLAUDE.md: "Never mark a milestone complete with [...] a check that emits a
 * finding with no `remediation`." A finding that tells an operator something is
 * broken and not what to do about it is a worse version of the error message
 * they already had.
 *
 * Applied in the engine to every finding a probe returns, so a probe cannot
 * ship a dead-end finding even by accident.
 */
export function assertRemediable(finding: Finding): void {
  const needsRemediation = finding.severity === 'blocker' || finding.severity === 'degraded';
  if (needsRemediation && (finding.remediation === undefined || finding.remediation.trim() === '')) {
    throw new Error(
      `finding '${finding.id}' has severity '${finding.severity}' but no remediation; ` +
        `write the remediation before writing the check`,
    );
  }
}
