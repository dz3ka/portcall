import { describe, expect, it } from 'vitest';
import { EXIT, exitCodeFor } from '../src/cli/exit-codes.ts';

describe('exitCodeFor', () => {
  it('maps ok to 0', () => {
    expect(exitCodeFor('ok')).toBe(EXIT.OK);
    expect(exitCodeFor('ok')).toBe(0);
  });

  it('maps degraded to 1', () => {
    expect(exitCodeFor('degraded')).toBe(EXIT.DEGRADED);
    expect(exitCodeFor('degraded')).toBe(1);
  });

  it('maps unknown to 1, not 0 — a check that ran and could not decide is not a pass', () => {
    expect(exitCodeFor('unknown')).toBe(EXIT.DEGRADED);
    expect(exitCodeFor('unknown')).toBe(1);
    expect(exitCodeFor('unknown')).not.toBe(EXIT.OK);
  });

  it('maps blocker to 2', () => {
    expect(exitCodeFor('blocker')).toBe(EXIT.BLOCKER);
    expect(exitCodeFor('blocker')).toBe(2);
  });

  it('reserves 3 for tool errors, not reachable from a severity', () => {
    expect(EXIT.TOOL_ERROR).toBe(3);
  });
});
