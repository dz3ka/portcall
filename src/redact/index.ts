import { createHash, randomBytes } from 'node:crypto';
import type { Evidence, EvidenceKind, Finding } from '../model/finding.ts';
import type { Report } from '../model/report.ts';

/**
 * Redaction (SPEC.md section 4.4, ADR-0005).
 *
 * The JSON that leaves a customer's network must be safe to email to a vendor
 * without a legal review. That is only true if redaction is *structurally*
 * unavoidable, not a courtesy each probe remembers to extend.
 *
 * The mechanism: the renderers accept `RedactedReport`, a branded type that
 * only `redact()` can produce. There is no cast to that type anywhere else in
 * the codebase, and a guardrail test asserts that. A future probe therefore
 * cannot emit an internal hostname into a report even if it tries, because it
 * has no path to a renderer that does not pass through this file.
 */

declare const redactionBrand: unique symbol;

/** A report that has passed the redaction boundary. Renderers accept only this. */
export type RedactedReport = Report & { readonly [redactionBrand]: true };

/** Evidence kinds that may identify the customer, their staff or their network. */
const SENSITIVE_KINDS: ReadonlySet<EvidenceKind> = new Set<EvidenceKind>([
  'hostname',
  'ip',
  'username',
  'serial',
  'path',
  'url',
  'dn',
]);

/** Short prefix in the emitted token, so a reader can tell what was hidden. */
const KIND_TAG: Readonly<Record<EvidenceKind, string>> = {
  hostname: 'host',
  ip: 'ip',
  username: 'user',
  serial: 'serial',
  path: 'path',
  url: 'url',
  dn: 'dn',
  public: 'public',
  text: 'text',
  number: 'number',
};

export interface RedactionOptions {
  /** False only for `--no-redact`, which prints a warning at the CLI edge. */
  enabled: boolean;
  /**
   * Values the vendor already knows: the endpoint hosts named in the active
   * profile. Hashing `api.anthropic.com` protects nobody and makes the report
   * unreadable, so profile-declared hosts stay in cleartext (ADR-0005).
   */
  publicValues?: readonly string[];
  /**
   * Per-report salt. Defaults to fresh random bytes so two reports from the
   * same customer cannot be correlated, and so a short internal hostname
   * cannot be recovered by hashing a wordlist. Injectable for tests only.
   */
  salt?: string;
}

export function newSalt(): string {
  return randomBytes(16).toString('hex');
}

function token(kind: EvidenceKind, value: string, salt: string): string {
  const digest = createHash('sha256').update(salt).update(' ').update(value).digest('hex');
  return `<${KIND_TAG[kind]}:${digest.slice(0, 12)}>`;
}

function normalisePublic(values: readonly string[]): ReadonlySet<string> {
  return new Set(values.map((value) => value.trim().toLowerCase()));
}

function redactEvidence(
  evidence: Evidence,
  salt: string,
  publicValues: ReadonlySet<string>,
): Evidence {
  if (!SENSITIVE_KINDS.has(evidence.kind)) return { ...evidence };
  if (publicValues.has(evidence.value.trim().toLowerCase())) return { ...evidence };
  return { ...evidence, value: token(evidence.kind, evidence.value, salt) };
}

function redactFinding(finding: Finding, salt: string, publicValues: ReadonlySet<string>): Finding {
  const redacted: Finding = {
    id: finding.id,
    probe: finding.probe,
    severity: finding.severity,
    title: finding.title,
    evidence: finding.evidence.map((item) => redactEvidence(item, salt, publicValues)),
  };
  if (finding.remediation !== undefined) redacted.remediation = finding.remediation;
  if (finding.docs !== undefined) redacted.docs = finding.docs;
  return redacted;
}

/**
 * The one and only entrance to the renderers.
 *
 * Note that this runs even when redaction is disabled: `--no-redact` changes
 * what the function does, never whether it is called. Keeping a single code
 * path means the "off" switch cannot drift into a second, unreviewed one.
 */
export function redact(report: Report, options: RedactionOptions): RedactedReport {
  const salt = options.salt ?? newSalt();
  const publicValues = normalisePublic(options.publicValues ?? []);

  const result: Report = {
    ...report,
    redacted: options.enabled,
    findings: options.enabled
      ? report.findings.map((finding) => redactFinding(finding, salt, publicValues))
      : report.findings.map((finding) => ({ ...finding })),
  };

  return result as RedactedReport;
}
