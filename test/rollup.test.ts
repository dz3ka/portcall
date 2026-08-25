import { describe, expect, it } from 'vitest';
import { rollUp, summarise, sortFindings } from '../src/engine/rollup.ts';
import { finding } from './helpers/report-fixture.ts';

describe('rollUp', () => {
  it('is ok for an empty set of findings', () => {
    expect(rollUp([])).toBe('ok');
  });

  it('is ok when every finding is ok', () => {
    expect(rollUp([finding({ severity: 'ok' }), finding({ severity: 'ok' })])).toBe('ok');
  });

  it('worst severity wins: blocker beats everything', () => {
    const findings = [
      finding({ severity: 'ok' }),
      finding({ severity: 'unknown' }),
      finding({ severity: 'degraded' }),
      finding({ severity: 'blocker' }),
    ];
    expect(rollUp(findings)).toBe('blocker');
  });

  it('worst severity wins: degraded beats unknown and ok', () => {
    const findings = [finding({ severity: 'ok' }), finding({ severity: 'unknown' }), finding({ severity: 'degraded' })];
    expect(rollUp(findings)).toBe('degraded');
  });

  it('worst severity wins: unknown beats ok', () => {
    const findings = [finding({ severity: 'ok' }), finding({ severity: 'unknown' })];
    expect(rollUp(findings)).toBe('unknown');
  });
});

describe('summarise', () => {
  it('counts each severity and reports the roll-up', () => {
    const findings = [
      finding({ id: 'a', severity: 'blocker', remediation: 'fix a' }),
      finding({ id: 'b', severity: 'degraded', remediation: 'fix b' }),
      finding({ id: 'c', severity: 'unknown' }),
      finding({ id: 'd', severity: 'ok' }),
      finding({ id: 'e', severity: 'ok' }),
    ];
    expect(summarise(findings)).toEqual({
      total: 5,
      blocker: 1,
      degraded: 1,
      unknown: 1,
      ok: 2,
      severity: 'blocker',
    });
  });

  it('summarises an empty set as ok with zero counts', () => {
    expect(summarise([])).toEqual({
      total: 0,
      blocker: 0,
      degraded: 0,
      unknown: 0,
      ok: 0,
      severity: 'ok',
    });
  });
});

describe('sortFindings', () => {
  it('orders worst severity first', () => {
    const findings = [
      finding({ id: 'z', probe: 'p', severity: 'ok' }),
      finding({ id: 'a', probe: 'p', severity: 'blocker', remediation: 'fix' }),
      finding({ id: 'm', probe: 'p', severity: 'degraded', remediation: 'fix' }),
    ];
    const sorted = sortFindings(findings);
    expect(sorted.map((f) => f.severity)).toEqual(['blocker', 'degraded', 'ok']);
  });

  it('breaks ties on severity by probe name', () => {
    const findings = [
      finding({ id: 'x', probe: 'zeta', severity: 'ok' }),
      finding({ id: 'y', probe: 'alpha', severity: 'ok' }),
    ];
    const sorted = sortFindings(findings);
    expect(sorted.map((f) => f.probe)).toEqual(['alpha', 'zeta']);
  });

  it('breaks ties on severity and probe by id', () => {
    const findings = [
      finding({ id: 'zeta.finding', probe: 'p', severity: 'ok' }),
      finding({ id: 'alpha.finding', probe: 'p', severity: 'ok' }),
    ];
    const sorted = sortFindings(findings);
    expect(sorted.map((f) => f.id)).toEqual(['alpha.finding', 'zeta.finding']);
  });

  it('does not mutate the input array', () => {
    const findings = [finding({ id: 'b', severity: 'ok' }), finding({ id: 'a', severity: 'blocker', remediation: 'fix' })];
    const original = [...findings];
    sortFindings(findings);
    expect(findings).toEqual(original);
  });
});
