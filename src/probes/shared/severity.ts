import type { Severity } from '../../model/finding.ts';

/**
 * Cap a severity by whether the endpoint is required by the profile.
 *
 * An optional endpoint (say `registry.npmjs.org` for a tool that ships its own
 * deps) being blocked is worth a `degraded`, never a `blocker` — a blocker
 * exits 2 and gates the customer's CI over something the tool works without.
 *
 * `unknown` is never capped. It is not a severity on the same axis: it means
 * the check could not decide, and how important the endpoint is has no bearing
 * on that. Capping it would also silently turn "we could not tell" into a
 * softer-sounding verdict we did not earn.
 */
export function cap(severity: Severity, required: boolean): Severity {
  if (required) return severity;

  switch (severity) {
    case 'blocker':
      return 'degraded';
    case 'degraded':
    case 'ok':
    case 'unknown':
      return severity;
  }
}
