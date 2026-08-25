import type { Severity } from '../model/finding.ts';

/**
 * Deterministic exit codes (ADR-0006). Customers run this in their own CI, so
 * these are API: changing one is a breaking change.
 */
export const EXIT = {
  /** No blockers. The tool should work here. */
  OK: 0,
  /** Works, with limitations. Also the code for `unknown` (see below). */
  DEGRADED: 1,
  /** At least one blocker. The tool will not work here as configured. */
  BLOCKER: 2,
  /** Portcall itself failed: bad arguments, unreadable profile, internal error. */
  TOOL_ERROR: 3,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/**
 * `unknown` maps to DEGRADED rather than OK.
 *
 * A check that ran and could not decide is not a pass. Mapping it to 0 would
 * let a customer's pipeline go green on a machine where the tool is in fact
 * unusable, which is precisely the failure this project exists to prevent.
 */
export function exitCodeFor(severity: Severity): ExitCode {
  switch (severity) {
    case 'blocker':
      return EXIT.BLOCKER;
    case 'degraded':
    case 'unknown':
      return EXIT.DEGRADED;
    case 'ok':
      return EXIT.OK;
  }
}
