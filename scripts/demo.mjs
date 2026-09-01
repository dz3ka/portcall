#!/usr/bin/env node
// The one-command demo: brings the hostile network up, runs a real `portcall
// check` inside it, prints the report, and tears the network down.
//
// It is the same four compose commands `test/harness/README.md` documents, in
// the same order, with the run step pointed at the CLI instead of the
// integration suite - so what an onlooker sees is the product, not vitest.
//
// The demo *requires* the check to exit 2 (ADR-0006's `blocker`, ADR-0046). A
// run of this network that finds nothing is a broken demo, not a passing one:
// the harness plants a proxy re-signing TLS with its own root, and a root the
// container's OS trusts that node's bundle does not, and portcall's whole claim
// is that it names both. Any other exit code fails this script.
//
// The network is torn down on every path - a failed `up`, a wrong exit code, an
// unexpected throw. The one path it cannot cover is a Ctrl-C, which kills this
// process along with the compose command it is waiting on; see "Known
// limitations" in test/harness/README.md.
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const COMPOSE_FILE = 'test/harness/docker-compose.yml';
/** Fixed in docker-compose.yml and in the DNS zone beside it. See bringUp(). */
const SUBNET = '10.31.0.0/24';
/** The harness profile, and the same file `harnessProfile()` parses (ADR-0046). */
const DEMO_PROFILE = 'test/harness/demo-profile.yaml';
/** The re-signing proxy, by its name in the harness DNS zone - what an operator's env holds. */
const INTERCEPTING_PROXY = 'http://mitmproxy:8080';
/** ADR-0006: at least one blocker. The demo's pass condition, not an accident of it. */
const EXPECTED_CHECK_EXIT = 2;

/** A failure this script has something useful to say about, as opposed to a bug in it. */
class DemoError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DemoError';
  }
}

/**
 * One `docker compose` step, inheriting stdio so the demo *is* the terminal
 * output. Returns the child's exit status; a spawn failure is the one thing it
 * turns into a throw, because "docker is not installed" and "docker said no"
 * are two different tickets.
 */
function compose(label, args) {
  console.log(`\n==> ${label}`);
  const result = spawnSync('docker', ['compose', '-f', COMPOSE_FILE, ...args], {
    cwd: root,
    stdio: 'inherit',
  });
  if (result.error !== undefined) {
    throw new DemoError(
      [
        `could not run \`docker\` (${result.error.code}).`,
        'The demo needs Docker with compose v2 - `docker compose`, not `docker-compose`.',
        '',
        '  install it:  https://docs.docker.com/get-docker/',
        '  or:          run everything that needs no Docker: npm run verify',
      ].join('\n'),
    );
  }
  return result.status;
}

/**
 * Brings the five services up and waits for every healthcheck.
 *
 * The failure worth naming is the subnet. The harness takes a fixed range so
 * that every address in `docker-compose.yml` is also the address in the DNS
 * zone, and on a machine already using that range compose refuses the network.
 * Compose's own message ("Pool overlaps with other one on this address space")
 * is the diagnosis; this only says which range it is talking about, and where
 * the limitation is written down.
 */
function bringUp() {
  const status = compose('docker compose up --wait   (five services, each healthchecked)', [
    'up',
    '--wait',
  ]);
  if (status === 0) return;

  throw new DemoError(
    [
      `\`docker compose up --wait\` exited ${status}; the output above says why.`,
      '',
      `The harness network takes a fixed subnet, ${SUBNET}, because ${COMPOSE_FILE} and`,
      'test/harness/dns/dnsmasq.conf name the same addresses and have to agree. If compose',
      'reported a pool overlap, something on this machine already holds that range - another',
      'compose project, a VPN, or a host route. Free it and run the demo again.',
      '',
      'See "Known limitations" in test/harness/README.md.',
    ].join('\n'),
  );
}

/**
 * Runs the product inside the network.
 *
 * `build portcall` first is not optional: the image bakes the repo with
 * `COPY . .` and nothing is bind-mounted, so a run after an edit would demo the
 * tree as it stood at the last build.
 */
function runCheck() {
  const buildStatus = compose('docker compose build portcall   (the image bakes the repo)', [
    'build',
    'portcall',
  ]);
  if (buildStatus !== 0) {
    throw new DemoError(
      `\`docker compose build portcall\` exited ${buildStatus}; the output above says why.`,
    );
  }

  // The service's own command runs the integration suite; this replaces it with
  // the CLI. The entrypoint is deliberately left alone - it is what plants
  // mitmproxy's root in the container's own OS trust store (ADR-0041), which is
  // the condition the truststore finding in the report below reports.
  const checkStatus = compose(
    `docker compose run --rm portcall   (portcall check, HTTPS_PROXY=${INTERCEPTING_PROXY})`,
    [
      'run',
      '--rm',
      '-e',
      `HTTPS_PROXY=${INTERCEPTING_PROXY}`,
      'portcall',
      'node',
      'src/cli/index.ts',
      'check',
      '--profile',
      DEMO_PROFILE,
      '--format',
      'text',
    ],
  );
  if (checkStatus === EXPECTED_CHECK_EXIT) return;

  throw new DemoError(
    [
      `the check exited ${checkStatus}; this demo requires ${EXPECTED_CHECK_EXIT}.`,
      '',
      'Exit 2 is `blocker` (ADR-0006), and here it is the pass condition rather than a',
      'failure: the network above plants a proxy re-signing TLS with its own root, and a',
      'root the container trusts that node does not, so a run coming back with no blocker',
      'has demonstrated nothing.',
      '',
      '  0 or 1 - portcall ran and found no blocker. A planted condition did not reach the',
      '           probes: the report above says which findings it did emit, and',
      '           `npm run test:integration` inside the network says which condition broke.',
      '  3      - portcall itself failed: bad arguments, an unreadable profile, an internal',
      `           error. The output above names it; ${DEMO_PROFILE} is the profile it read.`,
    ].join('\n'),
  );
}

/**
 * Always runs, and never replaces the failure that got us here: a teardown that
 * masked the real error would make every failure look like a Docker problem.
 * It reports its own trouble and hands back the command that finishes the job.
 */
function tearDown() {
  console.log('\n==> docker compose down -v --remove-orphans');
  const result = spawnSync(
    'docker',
    ['compose', '-f', COMPOSE_FILE, 'down', '-v', '--remove-orphans'],
    { cwd: root, stdio: 'inherit' },
  );
  if (result.error === undefined && result.status === 0) return;

  console.error(
    [
      'teardown did not complete cleanly. The harness network or its `mitm-ca` volume may',
      'still exist, and leaving the volume behind means the next run reuses mitmproxy\'s',
      'root instead of exercising cold-start generation. Finish it by hand:',
      '',
      `  docker compose -f ${COMPOSE_FILE} down -v --remove-orphans`,
    ].join('\n'),
  );
}

// No flags. The demo runs the whole network or it is not a demo, and an unknown
// argument is an error rather than a silent no-op.
if (process.argv.length > 2) {
  console.error(
    `unknown argument ${JSON.stringify(process.argv[2])}; usage: node scripts/demo.mjs`,
  );
  process.exit(1);
}

let failure;
try {
  bringUp();
  runCheck();
} catch (error) {
  failure = error;
}

tearDown();

if (failure !== undefined) {
  console.error(
    `\n${failure instanceof DemoError ? failure.message : String(failure.stack ?? failure)}`,
  );
  process.exit(1);
}

console.log(
  `\ndemo complete: the check reported blockers (exit ${EXPECTED_CHECK_EXIT}) and the network is down.`,
);
