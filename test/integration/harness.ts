import type { ProbeContext } from '../../src/engine/index.ts';
import { NetworkGuard } from '../../src/net/guard.ts';
import type { Finding } from '../../src/model/finding.ts';
import type { Endpoint, LoadedProfile, Profile } from '../../src/profiles/schema.ts';

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
 * It is a fixture rather than a loosening of `NetworkGuard`: SPEC.md §4 says
 * portcall contacts no host the active profile did not name, and the harness
 * gets its endpoints admitted the same way a customer's would - by being in a
 * profile. The two hosts are the real public names the shipped profile uses,
 * which is what makes the DNS scenario a *split horizon* rather than a private
 * name resolving privately.
 *
 * `interception_tolerated: false` is deliberate. It is the setting that makes
 * `tls.private-root` a `blocker` instead of a `degraded`, and severity is API
 * here in the same way finding ids are - a harness that only ever exercised the
 * lenient branch would let the strict one rot.
 */
export function harnessProfile(): LoadedProfile {
  const endpoints: Endpoint[] = [
    {
      host: 'api.anthropic.com',
      port: 443,
      purpose: 'harness origin, reached over TLS',
      required: true,
      expect_streaming: false,
    },
    {
      // Non-443 on purpose: this is the endpoint routed through the proxy that
      // will not tunnel. The tls probe ignores it (it captures 443 only), which
      // is why the interception scenario is unaffected by its presence.
      host: 'registry.npmjs.org',
      port: 8080,
      purpose: 'harness endpoint on a port the refusing proxy will not tunnel',
      required: false,
      expect_streaming: false,
    },
  ];

  const profile: Profile = {
    name: 'Portcall hostile-network harness',
    endpoints,
    doh_resolvers: [],
    runtimes: ['node'],
    tls: { min_version: '1.2', interception_tolerated: false },
  };

  return { id: 'harness', source: 'builtin', profile };
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
