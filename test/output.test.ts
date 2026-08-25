import { describe, expect, it, afterEach, beforeEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveOutputPath, writeReport, OutputPathError } from '../src/cli/output.ts';

describe('resolveOutputPath (cwd confinement)', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'portcall-output-'));

  it('accepts a plain relative path inside cwd', () => {
    const resolved = resolveOutputPath('report.json', cwd);
    expect(resolved).toBe(join(cwd, 'report.json'));
  });

  it('accepts a nested relative path inside cwd', () => {
    const resolved = resolveOutputPath('reports/today.json', cwd);
    expect(resolved).toBe(join(cwd, 'reports', 'today.json'));
  });

  it('refuses a relative path that escapes cwd with ../', () => {
    expect(() => resolveOutputPath('../escape.json', cwd)).toThrow(OutputPathError);
  });

  it('refuses an absolute path outside cwd', () => {
    const outsideAbsolute = join(tmpdir(), 'portcall-output-elsewhere', 'x.json');
    expect(() => resolveOutputPath(outsideAbsolute, cwd)).toThrow(OutputPathError);
  });

  it('refuses cwd itself (empty relative path)', () => {
    expect(() => resolveOutputPath('.', cwd)).toThrow(OutputPathError);
  });

  if (process.platform === 'win32') {
    it('refuses a Windows-style backslash traversal ..\\ outside cwd', () => {
      expect(() => resolveOutputPath('..\\escape.json', cwd)).toThrow(OutputPathError);
    });
  }

  it('the thrown error explains why and does not silently obey', () => {
    try {
      resolveOutputPath('../escape.json', cwd);
      throw new Error('expected resolveOutputPath to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(OutputPathError);
      if (error instanceof OutputPathError) {
        expect(error.message).toContain('refusing to write');
        expect(error.message).toContain('does not write outside the');
      }
    }
  });
});

describe('writeReport', () => {
  let cwd: string;

  beforeEach(() => {
    cwd = mkdtempSync(join(tmpdir(), 'portcall-output-write-'));
  });

  afterEach(() => {
    rmSync(cwd, { recursive: true, force: true });
  });

  it('writes contents inside cwd and returns the resolved path', async () => {
    const written = await writeReport('report.json', cwd, '{"ok":true}');
    expect(written).toBe(join(cwd, 'report.json'));
    expect(readFileSync(written, 'utf8')).toBe('{"ok":true}');
  });

  it('refuses to write outside cwd and does not create the file', async () => {
    await expect(writeReport('../escape.json', cwd, 'nope')).rejects.toThrow(OutputPathError);
  });
});
