import { describe, expect, it } from 'vitest';
import { parseArgs, DEFAULT_TIMEOUT_SECONDS, type CheckCommand } from '../src/cli/args.ts';

describe('parseArgs', () => {
  it('returns help when no arguments are given', () => {
    const result = parseArgs([]);
    expect(result).toEqual({ ok: true, command: { kind: 'help' } });
  });

  it.each([['-h'], ['--help'], ['help']])('recognises %s as help', (flag) => {
    const result = parseArgs([flag]);
    expect(result).toEqual({ ok: true, command: { kind: 'help' } });
  });

  it.each([['-v'], ['--version'], ['version']])('recognises %s as version', (flag) => {
    const result = parseArgs([flag]);
    expect(result).toEqual({ ok: true, command: { kind: 'version' } });
  });

  it('accepts --help anywhere in a check command', () => {
    const result = parseArgs(['check', '--profile', 'generic-ai-tool', '--help']);
    expect(result).toEqual({ ok: true, command: { kind: 'help' } });
  });

  it('parses the profiles command', () => {
    const result = parseArgs(['profiles']);
    expect(result).toEqual({ ok: true, command: { kind: 'profiles' } });
  });

  it('rejects an extra argument after profiles', () => {
    const result = parseArgs(['profiles', 'extra']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("after 'profiles'");
  });

  it('rejects an unknown top-level command', () => {
    const result = parseArgs(['bogus']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown command 'bogus'");
  });

  it('parses a minimal check command with defaults', () => {
    const result = parseArgs(['check', '--profile', 'generic-ai-tool']);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('expected ok');
    const command = result.command as CheckCommand;
    expect(command).toEqual({
      kind: 'check',
      profile: 'generic-ai-tool',
      format: 'text',
      redact: true,
      timeoutMs: DEFAULT_TIMEOUT_SECONDS * 1000,
    });
  });

  it('requires --profile for check', () => {
    const result = parseArgs(['check']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('--profile');
  });

  it('rejects --profile with no value', () => {
    const result = parseArgs(['check', '--profile']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('--profile needs a value');
  });

  it('rejects --profile followed by another flag', () => {
    const result = parseArgs(['check', '--profile', '--format']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('--profile needs a value');
  });

  it('parses --profile=value inline form', () => {
    const result = parseArgs(['check', '--profile=generic-ai-tool']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') {
      expect(result.command.profile).toBe('generic-ai-tool');
    }
  });

  it.each(['json', 'html', 'text'] as const)('accepts --format %s', (format) => {
    const result = parseArgs(['check', '--profile', 'p', '--format', format]);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.format).toBe(format);
  });

  it('accepts --format=value inline form', () => {
    const result = parseArgs(['check', '--profile', 'p', '--format=json']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.format).toBe('json');
  });

  it('rejects an unknown format', () => {
    const result = parseArgs(['check', '--profile', 'p', '--format', 'xml']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown format 'xml'");
  });

  it('rejects --format with no value', () => {
    const result = parseArgs(['check', '--profile', 'p', '--format']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('--format needs a value');
  });

  it('parses --out', () => {
    const result = parseArgs(['check', '--profile', 'p', '--out', 'report.json']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.out).toBe('report.json');
  });

  it('parses --out=value inline form', () => {
    const result = parseArgs(['check', '--profile', 'p', '--out=report.json']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.out).toBe('report.json');
  });

  it('rejects --out with no value', () => {
    const result = parseArgs(['check', '--profile', 'p', '--out']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('--out needs a value');
  });

  it('leaves out undefined when --out is not given', () => {
    const result = parseArgs(['check', '--profile', 'p']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.out).toBeUndefined();
  });

  it('parses --timeout in seconds and converts to milliseconds', () => {
    const result = parseArgs(['check', '--profile', 'p', '--timeout', '30']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.timeoutMs).toBe(30_000);
  });

  it('parses --timeout=value inline form', () => {
    const result = parseArgs(['check', '--profile', 'p', '--timeout=15']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.timeoutMs).toBe(15_000);
  });

  it('rejects a non-numeric --timeout', () => {
    const result = parseArgs(['check', '--profile', 'p', '--timeout', 'soon']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('positive number of seconds');
  });

  it('rejects a zero or negative --timeout', () => {
    for (const value of ['0', '-5']) {
      const result = parseArgs(['check', '--profile', 'p', '--timeout', value]);
      expect(result.ok).toBe(false);
    }
  });

  it('rejects a --timeout above the maximum', () => {
    const result = parseArgs(['check', '--profile', 'p', '--timeout', '3601']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('at most 3600 seconds');
  });

  it('rejects --timeout with no value', () => {
    const result = parseArgs(['check', '--profile', 'p', '--timeout']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe('--timeout needs a value');
  });

  it('parses --no-redact', () => {
    const result = parseArgs(['check', '--profile', 'p', '--no-redact']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.redact).toBe(false);
  });

  it('defaults redact to true', () => {
    const result = parseArgs(['check', '--profile', 'p']);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') expect(result.command.redact).toBe(true);
  });

  it('rejects an unknown option', () => {
    const result = parseArgs(['check', '--profile', 'p', '--bogus']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown option '--bogus'");
  });

  it('combines every flag together', () => {
    const result = parseArgs([
      'check',
      '--profile',
      'my-profile.yaml',
      '--format',
      'json',
      '--out',
      'out.json',
      '--timeout',
      '10',
      '--no-redact',
    ]);
    expect(result.ok).toBe(true);
    if (result.ok && result.command.kind === 'check') {
      expect(result.command).toEqual({
        kind: 'check',
        profile: 'my-profile.yaml',
        format: 'json',
        redact: false,
        timeoutMs: 10_000,
        out: 'out.json',
      });
    }
  });
});
