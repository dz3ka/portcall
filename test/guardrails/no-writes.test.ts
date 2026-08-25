import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * SPEC.md 4.1 / CLAUDE.md non-negotiable: no writes outside the working
 * directory. No installs, no config mutation.
 *
 * This is an inventory diff, not a kernel-level trace: we snapshot every file
 * under a sandboxed HOME/USERPROFILE and a sandboxed "OS temp dir" (redirected
 * via TEMP/TMP/TMPDIR so we are not at the mercy of whatever else a shared CI
 * runner happens to be doing in the real system temp directory at the same
 * moment) before and after running the CLI as a child process, and fail on any
 * new or modified file outside the run's own `cwd`. A real filesystem watcher
 * (fanotify / FSEvents / ReadDirectoryChangesW) would be a stronger check, but
 * is not portable across the three CI runners this project targets
 * (Windows/macOS/Linux) — this is the honest, portable substitute.
 */

interface Inventory {
  [relativePath: string]: { size: number; mtimeMs: number };
}

function snapshot(dir: string): Inventory {
  const inventory: Inventory = {};
  const walk = (current: string, prefix: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(full, rel);
      } else if (entry.isFile()) {
        const stat = statSync(full);
        inventory[rel] = { size: stat.size, mtimeMs: stat.mtimeMs };
      }
    }
  };
  walk(dir, '');
  return inventory;
}

function diff(before: Inventory, after: Inventory): string[] {
  const problems: string[] = [];
  for (const [path, info] of Object.entries(after)) {
    const previous = before[path];
    if (previous === undefined) {
      problems.push(`new file: ${path}`);
    } else if (previous.size !== info.size || previous.mtimeMs !== info.mtimeMs) {
      problems.push(`modified file: ${path}`);
    }
  }
  for (const path of Object.keys(before)) {
    if (!(path in after)) problems.push(`deleted file: ${path}`);
  }
  return problems;
}

const CLI_ENTRY = join(import.meta.dirname, '..', '..', 'src', 'cli', 'index.ts');

describe('no writes outside cwd guardrail', () => {
  it('running `check` writes nothing outside its own cwd', () => {
    const root = mkdtempSync(join(tmpdir(), 'portcall-guard-nowrite-'));
    const home = join(root, 'home');
    const sandboxTemp = join(root, 'temp');
    const runCwd = join(root, 'cwd');
    mkdirSync(home);
    mkdirSync(sandboxTemp);
    mkdirSync(runCwd);

    try {
      const before = { home: snapshot(home), temp: snapshot(sandboxTemp) };

      const result = spawnSync(
        process.execPath,
        [CLI_ENTRY, 'check', '--profile', 'generic-ai-tool', '--format', 'text'],
        {
          cwd: runCwd,
          env: {
            PATH: process.env['PATH'],
            Path: process.env['Path'],
            HOME: home,
            USERPROFILE: home,
            TEMP: sandboxTemp,
            TMP: sandboxTemp,
            TMPDIR: sandboxTemp,
          },
          encoding: 'utf8',
          timeout: 30_000,
        },
      );

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);

      const after = { home: snapshot(home), temp: snapshot(sandboxTemp) };

      expect(diff(before.home, after.home)).toEqual([]);
      expect(diff(before.temp, after.temp)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('a --out target inside cwd is written, and nothing outside cwd changes', () => {
    const root = mkdtempSync(join(tmpdir(), 'portcall-guard-nowrite-out-'));
    const home = join(root, 'home');
    const sandboxTemp = join(root, 'temp');
    const runCwd = join(root, 'cwd');
    mkdirSync(home);
    mkdirSync(sandboxTemp);
    mkdirSync(runCwd);

    try {
      const before = { home: snapshot(home), temp: snapshot(sandboxTemp) };

      const result = spawnSync(
        process.execPath,
        [CLI_ENTRY, 'check', '--profile', 'generic-ai-tool', '--format', 'json', '--out', 'report.json'],
        {
          cwd: runCwd,
          env: {
            PATH: process.env['PATH'],
            Path: process.env['Path'],
            HOME: home,
            USERPROFILE: home,
            TEMP: sandboxTemp,
            TMP: sandboxTemp,
            TMPDIR: sandboxTemp,
          },
          encoding: 'utf8',
          timeout: 30_000,
        },
      );

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);

      // The file was written where asked, inside cwd.
      const cwdInventory = snapshot(runCwd);
      expect(cwdInventory['report.json']).toBeDefined();

      // Nothing outside cwd (home, sandboxed temp) changed.
      const after = { home: snapshot(home), temp: snapshot(sandboxTemp) };
      expect(diff(before.home, after.home)).toEqual([]);
      expect(diff(before.temp, after.temp)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
