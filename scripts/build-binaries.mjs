#!/usr/bin/env node
// Builds the release artifacts described in SPEC.md 5: one self-contained
// executable per platform plus SHA-256 sums, from a single entrypoint.
//
// `bun build --compile` is the compiler (ADR-0001) and cross-compiles all five
// targets from one runner, so this script is the whole release build - CI calls
// it once rather than per-OS. Bun is a build-time dependency only; nothing on
// the customer's machine needs it.
//
// Output goes to `build/binaries/` and not `dist/`: `dist/` is the tsc output
// that package.json `files` publishes to npm, and a 60 MB executable per
// platform has no business in the npx path.
//
// `--dry-run` prints the plan (targets, bun argv, output paths) without needing
// bun on PATH, which is how everything except the compile step is checked on a
// machine that has no bun.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = join(root, 'src', 'cli', 'index.ts');
const defaultOutDir = join(root, 'build', 'binaries');

// The five platforms SPEC.md 5 names, in SPEC order. `platform` is the name the
// release artifact carries; `bunTarget` is what `--target=` wants, and the two
// differ on Windows (`win-x64` vs bun's `bun-windows-x64`), which is the only
// reason this is a table and not a string template.
const TARGETS = Object.freeze([
  { platform: 'darwin-arm64', bunTarget: 'bun-darwin-arm64', exe: false },
  { platform: 'darwin-x64', bunTarget: 'bun-darwin-x64', exe: false },
  { platform: 'linux-x64', bunTarget: 'bun-linux-x64', exe: false },
  { platform: 'linux-arm64', bunTarget: 'bun-linux-arm64', exe: false },
  { platform: 'win-x64', bunTarget: 'bun-windows-x64', exe: true },
]);

const CHECKSUM_FILE = 'SHA256SUMS';

/** Artifact filename for a target. Pure. */
function artifactName(target) {
  return `portcall-${target.platform}${target.exe ? '.exe' : ''}`;
}

/** `bun` argv for one target. Pure, so the command is readable under --dry-run. */
function bunArgs(target, outDir) {
  return [
    'build',
    '--compile',
    `--target=${target.bunTarget}`,
    entrypoint,
    '--outfile',
    join(outDir, artifactName(target)),
  ];
}

/**
 * `sha256sum -c` format: lowercase hex, two spaces, filename with no directory
 * part, sorted by name so the file is byte-identical across runs on any host.
 * Pure.
 */
function formatChecksums(entries) {
  return (
    [...entries]
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((entry) => `${entry.digest}  ${entry.name}`)
      .join('\n') + '\n'
  );
}

/**
 * `--dry-run` prints the plan instead of compiling, and is the only flag: a
 * release builds all five targets, into one place, or it is not a release.
 * Unknown arguments are errors rather than silent no-ops - a release that
 * quietly built four of five targets is the failure mode worth being loud
 * about. Pure: returns a plan or throws.
 */
function parsePlan(argv) {
  let dryRun = false;

  for (const arg of argv) {
    if (arg === '--dry-run') {
      dryRun = true;
    } else {
      throw new Error(
        `unknown argument ${JSON.stringify(arg)}; usage: node scripts/build-binaries.mjs [--dry-run]`,
      );
    }
  }

  return { targets: [...TARGETS], outDir: defaultOutDir, dryRun };
}

/**
 * Runs `bun` with the given argv. `shell` is not a style preference: on Windows
 * the documented install (`npm i -g bun`) drops a `bun.cmd` shim, which
 * CreateProcess cannot execute and Node refuses to run without a shell - so a
 * shell-less spawn reports ENOENT for a bun that is plainly on PATH. requireBun()
 * decides the flag once and hands it back, so the version probe and the five
 * build spawns cannot disagree about how bun is invoked on this host.
 */
function spawnBun(args, { shell, ...options }) {
  // cmd.exe splits the command line on spaces, so the absolute paths in argv
  // (the entrypoint and --outfile) need quoting; `"` is not a legal character in
  // a Windows filename, so nothing in these paths can escape the quotes.
  const argv = shell ? args.map((arg) => (/\s/.test(arg) ? `"${arg}"` : arg)) : args;
  return spawnSync('bun', argv, { ...options, shell });
}

/**
 * Fails before spawning anything, so a machine without bun gets one actionable
 * line instead of an ENOENT stack trace out of child_process. Returns how the
 * build spawns must invoke bun on this host.
 */
function requireBun() {
  // Plain spawn first: POSIX never needs a shell and neither does a real
  // bun.exe, so only a Windows spawn error earns the slower second attempt.
  let shell = false;
  let probe = spawnBun(['--version'], { encoding: 'utf8', shell });
  const spawnError = probe.error;
  if (spawnError !== undefined && process.platform === 'win32') {
    shell = true;
    probe = spawnBun(['--version'], { encoding: 'utf8', shell });
  }

  if (probe.error === undefined && probe.status === 0) {
    console.log(`bun ${probe.stdout.trim()}`);
    return { shell };
  }
  // "bun is missing" and "bun is here but broken" are two different tickets, and
  // the first spawn's error is what tells them apart: through a shell a missing
  // bun comes back as an ordinary non-zero exit, so the retry cannot be witness.
  if (spawnError === undefined) {
    console.error(
      `bun is on PATH but \`bun --version\` exited ${probe.status}:\n${(probe.stderr ?? '').trim()}`,
    );
    process.exit(1);
  }
  console.error(
    [
      'bun was not found on PATH, and it is what compiles the per-platform',
      'executables (SPEC.md 5, ADR-0001). It is a build-time dependency only -',
      'nothing on a customer machine needs it.',
      '',
      '  install it:  https://bun.sh/docs/installation  (or: npm i -g bun)',
      '  or:          let CI build the release artifacts; it runs this script',
      '  or:          node scripts/build-binaries.mjs --dry-run  to see the plan',
      '',
      'To build a runnable portcall without bun: npm run build && node dist/cli/index.js',
      '',
      `probe: \`bun --version\` failed with ${spawnError.code}${
        shell ? `, and again through a shell (for a bun.cmd shim) with exit ${probe.status}` : ''
      }`,
    ].join('\n'),
  );
  process.exit(1);
}

let plan;
try {
  plan = parsePlan(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

if (plan.dryRun) {
  console.log(`entrypoint: ${relative(root, entrypoint)}`);
  console.log(`out dir:    ${relative(root, plan.outDir)}`);
  for (const target of plan.targets) {
    console.log(`  bun ${bunArgs(target, plan.outDir).join(' ')}`);
  }
  console.log(`  -> ${join(relative(root, plan.outDir), CHECKSUM_FILE)}`);
  process.exit(0);
}

const bun = requireBun();

mkdirSync(plan.outDir, { recursive: true });

const checksums = [];
for (const target of plan.targets) {
  const name = artifactName(target);
  console.log(`building ${name} (${target.bunTarget})`);
  const result = spawnBun(bunArgs(target, plan.outDir), {
    cwd: root,
    stdio: 'inherit',
    shell: bun.shell,
  });
  if (result.status !== 0) {
    console.error(`bun build failed for ${target.platform} (exit ${result.status})`);
    process.exit(1);
  }
  const digest = createHash('sha256')
    .update(readFileSync(join(plan.outDir, name)))
    .digest('hex');
  checksums.push({ name, digest });
}

writeFileSync(join(plan.outDir, CHECKSUM_FILE), formatChecksums(checksums), 'utf8');
console.log(
  `built ${checksums.length} binary(ies) -> ${join(relative(root, plan.outDir), CHECKSUM_FILE)}`,
);
