import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseProfile, loadProfile, looksLikePath, ProfileError } from '../src/profiles/loader.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures', 'profiles');

async function fixture(name: string): Promise<string> {
  return readFile(join(FIXTURES, name), 'utf8');
}

describe('parseProfile', () => {
  it('accepts a valid profile and applies defaults', async () => {
    const text = await fixture('valid.yaml');
    const loaded = parseProfile('fixture', 'file', text);
    expect(loaded.id).toBe('fixture');
    expect(loaded.source).toBe('file');
    expect(loaded.profile.name).toBe('Fixture AI tool');
    expect(loaded.profile.endpoints).toHaveLength(2);
    expect(loaded.profile.endpoints[0]?.required).toBe(true);
    expect(loaded.profile.endpoints[1]?.required).toBe(false);
    expect(loaded.profile.tls).toEqual({ min_version: '1.2', interception_tolerated: false });
  });

  it('rejects an unknown key via zod .strict()', async () => {
    const text = await fixture('unknown-key.yaml');
    expect(() => parseProfile('fixture', 'file', text)).toThrow(ProfileError);
    try {
      parseProfile('fixture', 'file', text);
      throw new Error('expected parseProfile to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ProfileError);
      if (error instanceof ProfileError) {
        expect(error.message).toContain('failed validation');
        expect(error.message).toContain('tracking_pixel');
      }
    }
  });

  it('rejects a bad hostname', async () => {
    const text = await fixture('bad-hostname.yaml');
    expect(() => parseProfile('fixture', 'file', text)).toThrow(ProfileError);
  });

  it('rejects a bad port', async () => {
    const text = await fixture('bad-port.yaml');
    expect(() => parseProfile('fixture', 'file', text)).toThrow(ProfileError);
  });

  it('rejects duplicate endpoints (case-insensitive host)', async () => {
    const text = await fixture('duplicate-endpoints.yaml');
    expect(() => parseProfile('fixture', 'file', text)).toThrow(ProfileError);
    try {
      parseProfile('fixture', 'file', text);
      throw new Error('expected parseProfile to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ProfileError);
      if (error instanceof ProfileError) expect(error.message).toContain('duplicate endpoints');
    }
  });

  it('rejects malformed YAML', async () => {
    const text = await fixture('malformed.yaml');
    expect(() => parseProfile('fixture', 'file', text)).toThrow(ProfileError);
    try {
      parseProfile('fixture', 'file', text);
      throw new Error('expected parseProfile to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ProfileError);
      if (error instanceof ProfileError) expect(error.message).toContain('not valid YAML');
    }
  });
});

describe('loadProfile', () => {
  it('loads a built-in profile by name', async () => {
    const loaded = await loadProfile('generic-ai-tool');
    expect(loaded.source).toBe('builtin');
    expect(loaded.profile.name).toBe('Generic AI developer tool');
  });

  it('rejects an unknown built-in profile name', async () => {
    await expect(loadProfile('does-not-exist')).rejects.toThrow(ProfileError);
  });

  it('loads a profile from a file path', async () => {
    const path = join(FIXTURES, 'valid.yaml');
    const loaded = await loadProfile(path);
    expect(loaded.source).toBe('file');
    expect(loaded.profile.name).toBe('Fixture AI tool');
  });

  it('reports a missing profile file with a ProfileError, not a raw fs error', async () => {
    const path = join(FIXTURES, 'does-not-exist.yaml');
    await expect(loadProfile(path)).rejects.toThrow(ProfileError);
    try {
      await loadProfile(path);
      throw new Error('expected loadProfile to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ProfileError);
      if (error instanceof ProfileError) expect(error.message).toContain('cannot read profile file');
    }
  });
});

describe('looksLikePath', () => {
  it('treats a bare name as a built-in profile id', () => {
    expect(looksLikePath('generic-ai-tool')).toBe(false);
  });

  it('treats a forward-slash path as a file', () => {
    expect(looksLikePath('./profiles/mine.yaml')).toBe(true);
  });

  it('treats a backslash path as a file', () => {
    expect(looksLikePath('profiles\\mine.yaml')).toBe(true);
  });

  it('treats a bare .yaml/.yml filename as a file', () => {
    expect(looksLikePath('mine.yaml')).toBe(true);
    expect(looksLikePath('mine.yml')).toBe(true);
  });
});
