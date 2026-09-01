import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { ProbeContext } from '../../src/engine/index.ts';
import { NetworkGuard } from '../../src/net/guard.ts';
import type { Finding } from '../../src/model/finding.ts';
import { parseProfile } from '../../src/profiles/loader.ts';
import type { LoadedProfile } from '../../src/profiles/schema.ts';

/**
 * The harness-only profile and the guard that refuses to run without the
 * harness (SPEC.md §10, ADR-0025).
 *
 * Nothing here is a test. It is the fixture the integration suite runs against
 * plus one assertion that runs before every scenario: *is this process actually
 * inside the hostile network*. That check exists because the failure it
 * prevents is the expensive one - a suite that quietly skips when the stack is
 * absent reports green on a machine where none of it ran, and CLAUDE.md does
 * not let a milestone close on a skipped test.
 */

/** The command that brings the network up and runs this suite inside it. */
export const HARNESS_COMMAND = [
  'docker compose -f test/harness/docker-compose.yml up --wait',
  // build precedes every run: the image bakes the repo with `COPY . .` and
  // nothing is bind-mounted, so a run after an edit re-executes the old tree.
  'docker compose -f test/harness/docker-compose.yml build portcall',
  'docker compose -f test/harness/docker-compose.yml run --rm portcall',
  'docker compose -f test/harness/docker-compose.yml down -v',
].join('\n  ');

/**
 * The proxies the harness plants, by the condition each one stands for. These
 * are names in the harness DNS zone (`test/harness/dns/dnsmasq.conf`), not
 * container addresses, because that is what an operator's `HTTPS_PROXY` holds.
 */
export const HARNESS_PROXIES = {
  /** Re-signs TLS with a root CA it generated. */
  intercepting: 'http://mitmproxy:8080',
  /** Demands Basic authentication and is never given any. */
  authenticating: 'http://squid:3128',
  /** Answers the CONNECT itself rather than tunnelling it. */
  refusing: 'http://nginx-proxy:8888',
} as const;

/**
 * The harness profile.
 *
 * Parsed from `test/harness/demo-profile.yaml`, which is the single definition
 * of it: `npm run demo` hands the CLI that same path, so the demo and this
 * suite cannot drift into describing two different networks, and the file the
 * demo depends on is exercised by every harness run rather than only when
 * somebody records one (ADR-0046). The comments arguing the profile's contents
 * - why the hosts are real public names, why `interception_tolerated` is
 * `false` - live in the YAML, beside what they explain.
 *
 * Read through the real loader, not a hand-built object, so a profile that
 * stopped validating fails here the same way it would fail a customer.
 */
export function harnessProfile(): LoadedProfile {
  // Resolved against this module rather than the cwd: the suite's cwd is the
  // image's WORKDIR today, and that is not a property worth depending on. The
  // id is the path `npm run demo` gives the CLI, so a report produced either
  // way says the same thing about where the profile came from.
  const path = fileURLToPath(new URL('../harness/demo-profile.yaml', import.meta.url));
  return parseProfile('test/harness/demo-profile.yaml', 'file', readFileSync(path, 'utf8'));
}

/**
 * A context for one scenario. A fresh `NetworkGuard` per call, never a shared
 * one: the guard accumulates runtime-permitted proxies as probes admit them,
 * and a guard carried between scenarios would let a later one reach a proxy an
 * earlier one had permitted.
 */
export function harnessContext(profile: LoadedProfile = harnessProfile()): ProbeContext {
  return {
    profile,
    net: new NetworkGuard(profile.profile),
    // Generous, and never used as a pass condition: no scenario in this suite
    // asserts on time. It is here so a hung probe fails the run rather than
    // hanging CI, which is the same reason the `binaries` job has a timeout.
    deadline: Date.now() + 60_000,
    signal: new AbortController().signal,
    observedAnchors: [],
  };
}

/**
 * Fails the run - loudly, and with the command to fix it - unless this process
 * is inside the harness network.
 *
 * Deliberately not a skip. `vitest` would report a skipped file as a pale green
 * and a reader would believe the harness had run. Deliberately not a retry
 * either: the readiness of every service is a compose healthcheck, so anything
 * still unreachable here is broken rather than slow, and retrying it would turn
 * a diagnosable failure into a slow flake.
 */
export function requireHarness(): void {
  if (process.env.PORTCALL_HARNESS === '1') return;

  throw new Error(
    'the portcall integration suite must run inside the hostile-network harness, and this ' +
      'process is not (PORTCALL_HARNESS is unset). It is never part of `npm test` or `npm run ' +
      'verify` - it needs Docker, and a customer laptop that has none must still be able to run ' +
      'the whole default suite. Bring the network up and run the suite in it with:\n\n  ' +
      HARNESS_COMMAND +
      '\n\nSee test/harness/README.md for what each service plants and how to debug one.',
  );
}

/** Ids only, in the order the probe emitted them. The severity assertions use `findingById`. */
export function idsOf(findings: readonly Finding[]): string[] {
  return findings.map((finding) => finding.id);
}

/** The one finding with this id, or a failure naming everything that *was* emitted. */
export function findingById(findings: readonly Finding[], id: string): Finding {
  const matches = findings.filter((finding) => finding.id === id);
  if (matches.length !== 1) {
    throw new Error(
      `expected exactly one \`${id}\` finding, got ${String(matches.length)}. ` +
        `The run emitted: ${idsOf(findings).join(', ')}`,
    );
  }
  return matches[0] as Finding;
}

/** The value of one evidence label, for the assertions that are about *what was observed*. */
export function evidenceValue(finding: Finding, label: string): string | undefined {
  return finding.evidence.find((item) => item.label === label)?.value;
}

/**
 * Runs `body` with the environment a scenario needs, and puts the environment
 * back afterwards.
 *
 * `runTls` takes its environment as a parameter, but `runProxy` reads
 * `process.env` directly, so a scenario that wants a proxy discovered has to
 * set it there. Restoring is not tidiness: the scenarios run in one process,
 * and a leaked `HTTPS_PROXY` would silently give a later scenario a proxy it
 * never asked for.
 */
export async function withEnv<T>(overrides: Record<string, string | undefined>, body: () => Promise<T>): Promise<T> {
  const previous = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(overrides)) {
    previous.set(name, process.env[name]);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  try {
    return await body();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
