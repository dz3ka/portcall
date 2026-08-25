import { describe, expect, it } from 'vitest';
import { assertRemediable } from '../../src/model/finding.ts';
import { finding } from '../helpers/report-fixture.ts';

/**
 * CLAUDE.md: "Never mark a milestone complete with [...] a check that emits a
 * finding with no `remediation`." Enforced in code by `assertRemediable`.
 */
describe('assertRemediable guardrail', () => {
  it.each(['blocker', 'degraded'] as const)(
    'throws when a %s finding has no remediation',
    (severity) => {
      const f = finding({ severity });
      delete f.remediation;
      expect(() => assertRemediable(f)).toThrow(/no remediation/);
    },
  );

  it.each(['blocker', 'degraded'] as const)(
    'throws when a %s finding has a blank remediation',
    (severity) => {
      expect(() => assertRemediable(finding({ severity, remediation: '   ' }))).toThrow(/no remediation/);
    },
  );

  it.each(['blocker', 'degraded'] as const)(
    'does not throw when a %s finding has a remediation',
    (severity) => {
      expect(() => assertRemediable(finding({ severity, remediation: 'do the thing' }))).not.toThrow();
    },
  );

  it.each(['ok', 'unknown'] as const)(
    'does not require remediation for a %s finding',
    (severity) => {
      const f = finding({ severity });
      delete f.remediation;
      expect(() => assertRemediable(f)).not.toThrow();
    },
  );
});
