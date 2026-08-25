import type { Evidence, Finding } from '../model/finding.ts';
import { extractCode } from '../net/dns.ts';
import { NetworkPolicyError } from '../net/guard.ts';

/**
 * The finding the engine emits when a probe throws (ADR-0005).
 *
 * A probe that dies does not fail the run - a stranger's laptop should get
 * partial results, not a crash - so the throw has to become a `Finding`, and
 * that finding crosses the redaction boundary like any other. The trap is that
 * the obvious thing to put in it, `error.message`, is the least bounded string
 * in the tool: `NetworkPolicyError` embeds `host:port`, and Node's own errors
 * embed hostnames (`getaddrinfo ENOTFOUND internal.corp.example`), addresses
 * (`connect ECONNREFUSED 10.0.0.5:443`) and absolute paths (`ENOENT ... open
 * '/home/jdoe/...'`). As `text` evidence that message would reach the report
 * unhashed, because `redact/` hashes by declared kind and `text` is not a
 * sensitive kind.
 *
 * So this module never reads `error.message`, and never calls `String(error)`.
 * It reads exactly two things: which of three classes the error belongs to,
 * and - through `extractCode`, the same narrowing `net/dns.ts` uses for every
 * other code in the report - a machine code if the error carries one. A policy
 * denial additionally discloses the host it refused, but under
 * `kind: 'hostname'`, so redaction hashes it like any other internal name.
 *
 * Pure and dependency-free by design: the engine's catch is the one code path
 * with no fixture behind it, so it is worth being able to test directly.
 */

/**
 * What went wrong, in our own words. Three classes because they are three
 * different sentences to the operator: we refused, the clock ran out, or we do
 * not know. Nothing finer can be said honestly without reading the message.
 */
export type ProbeErrorClass = 'network-policy' | 'aborted' | 'unclassified';

/** Our stand-in for "the error carried no machine code". Never a remote string. */
const NO_CODE = 'unavailable';

/**
 * The only branch in this module that looks at the error at all.
 *
 * `name` is checked rather than reported: `AbortError`/`TimeoutError` are what
 * `AbortSignal.abort()` and `AbortSignal.timeout()` reject with, but `name` is
 * a writable string on any object, so it is safe to test and never safe to
 * carry into the report.
 */
function classifyProbeError(error: unknown): ProbeErrorClass {
  if (error instanceof NetworkPolicyError) return 'network-policy';
  if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
    return 'aborted';
  }
  return 'unclassified';
}

/**
 * Written per class, and interpolating nothing but the probe name - a literal
 * from `registry.ts`. `remediation` bypasses redaction entirely
 * (`redact/index.ts` copies it through verbatim), so nothing remote-derived may
 * appear here. The `switch` is over the closed union on purpose:
 * `switch-exhaustiveness-check` makes a fourth class a build failure rather
 * than a finding with no advice on it.
 */
function remediationFor(probeName: string, errorClass: ProbeErrorClass): string {
  switch (errorClass) {
    case 'network-policy':
      return (
        `The ${probeName} probe tried to contact a host the active profile does not name, ` +
        `and portcall refused. Add that host to the profile if it belongs there, or send this ` +
        `report to the tool vendor - a probe reaching outside the profile is a bug. ` +
        `Other probes in this run are unaffected.`
      );
    case 'aborted':
      return (
        `The ${probeName} probe ran out of time. Re-run with --timeout raised. ` +
        `Other probes in this run are unaffected; only ${probeName} results are missing.`
      );
    case 'unclassified':
      return (
        `Re-run with --timeout raised, and send this report to the tool vendor. ` +
        `Other probes in this run are unaffected; only ${probeName} results are missing.`
      );
  }
}

/**
 * Turn a probe's throw into the `<probe>.probe-error` finding. `unknown`
 * severity: it is never capped, and it exits non-zero (ADR-0006), so a probe
 * that died cannot be read as a probe that passed.
 */
export function probeErrorFinding(probeName: string, error: unknown): Finding {
  const errorClass = classifyProbeError(error);

  const evidence: Evidence[] = [
    { label: 'error class', value: errorClass, kind: 'text' },
    { label: 'code', value: extractCode(error) ?? NO_CODE, kind: 'text' },
  ];

  // Appended last so the class and the code read first. `instanceof` again
  // rather than a cast off `errorClass`: this is TypeScript's narrowing to
  // reach `.host`, and a cast would be a second, unchecked classification.
  if (error instanceof NetworkPolicyError) {
    evidence.push({ label: 'host', value: error.host, kind: 'hostname' });
  }

  return {
    id: `${probeName}.probe-error`,
    probe: probeName,
    severity: 'unknown',
    title: `The ${probeName} probe could not complete`,
    evidence,
    remediation: remediationFor(probeName, errorClass),
  };
}
