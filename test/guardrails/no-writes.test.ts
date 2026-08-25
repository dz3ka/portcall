import { describe, expect, it } from 'vitest';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXIT } from '../../src/cli/exit-codes.ts';

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

/**
 * The spawned run uses a loopback-only profile, not the built-in one.
 *
 * Portcall contacts exactly the hosts the active profile names, so a profile
 * naming only `127.0.0.1` is what keeps this guardrail off the network - and
 * it has to stay off it. What is under test here is where the CLI *writes*,
 * and running the built-in profile would make the answer depend on whether the
 * machine can reach `api.anthropic.com`: on a firewalled, offline or proxied CI
 * runner the guardrail would fail for a reason it does not test. The whole CLI
 * path (profile load, both probes, render, `--out`) is still exercised, which
 * is what the write inventory is actually watching.
 */
const LOOPBACK_PROFILE = join(import.meta.dirname, '..', 'fixtures', 'profiles', 'loopback.yaml');

/**
 * Codes a completed `check` may exit with. `TOOL_ERROR` is excluded on
 * purpose: it would mean the CLI never got as far as running the checks, and a
 * run that died early proves nothing about what a real run writes.
 *
 * The verdict itself is deliberately not asserted - `degraded` here, `blocker`
 * on a runner where something answers on port 9 - but "any exit code" must not
 * become "any outcome", so a signal death, a missing status, or a crash before
 * the report is rendered all still fail.
 */
const COMPLETED_EXIT_CODES: readonly number[] = [EXIT.OK, EXIT.DEGRADED, EXIT.BLOCKER];

function expectCompletedRun(result: SpawnSyncReturns<string>): void {
  expect(result.error).toBeUndefined();
  expect(result.signal).toBeNull();
  expect(COMPLETED_EXIT_CODES).toContain(result.status);
}

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
        [CLI_ENTRY, 'check', '--profile', LOOPBACK_PROFILE, '--format', 'text'],
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

      expectCompletedRun(result);
      // The rendered report on stdout is the proof the run reached the end.
      expect(result.stdout).toContain('Loopback guardrail fixture');

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
        [CLI_ENTRY, 'check', '--profile', LOOPBACK_PROFILE, '--format', 'json', '--out', 'report.json'],
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

      expectCompletedRun(result);

      // The file was written where asked, inside cwd, and holds a whole report
      // rather than whatever a half-finished run left behind.
      const cwdInventory = snapshot(runCwd);
      expect(cwdInventory['report.json']).toBeDefined();
      const written: unknown = JSON.parse(readFileSync(join(runCwd, 'report.json'), 'utf8'));
      expect(written).toMatchObject({ profile: { name: 'Loopback guardrail fixture' } });

      // Nothing outside cwd (home, sandboxed temp) changed.
      const after = { home: snapshot(home), temp: snapshot(sandboxTemp) };
      expect(diff(before.home, after.home)).toEqual([]);
      expect(diff(before.temp, after.temp)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
