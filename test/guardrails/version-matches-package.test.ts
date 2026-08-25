import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { VERSION } from '../../src/version.ts';

describe('version matches package.json guardrail', () => {
  it('src/version.ts VERSION equals package.json version', async () => {
    const packageJsonPath = join(import.meta.dirname, '..', '..', 'package.json');
    const raw = await readFile(packageJsonPath, 'utf8');
    const pkg = JSON.parse(raw) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
