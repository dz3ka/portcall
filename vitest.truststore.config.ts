import { defineConfig } from 'vitest/config';

/**
 * The three-OS trust-store proof (M4, WP7, SPEC.md §7).
 *
 * A separate config from `vitest.config.ts`, for the same reason
 * `vitest.integration.config.ts` is: this suite needs something the default
 * suite must not depend on. There it was Docker; here it is a root certificate
 * injected into the *real* machine trust store by the CI workflow before this
 * runs (`.github/workflows/ci.yml`'s `truststore-proof` job) - not something a
 * fresh clone or a customer's laptop has, and not something this repo may ever
 * do to a machine it does not own (CLAUDE.md's "no config mutation" rule is
 * about the tool under test, not the harness that proves it; the harness lives
 * entirely inside a disposable CI runner).
 *
 * `npm run test:truststore` is never part of `npm test` or `npm run verify`.
 * It is run by the `truststore-proof` job only, after injection, and the
 * suite's own `requireInjectedRoot()` throws - never skips - if it is run
 * anywhere the injection did not happen, so a developer running it by
 * accident on a laptop gets a loud, actionable error rather than a silent
 * false pass.
 */
export default defineConfig({
  test: {
    include: ['test/truststore-injected/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Zero, matching the integration config's reasoning: a flaky pass here
    // would hide a real per-OS discrepancy in how the probe reads a trust
    // store, which is the one thing this suite exists to catch.
    retry: 0,
    // One file today, and the point of the gate below (module-scope reads of
    // a real, mutated machine store) is not something a second file racing it
    // should ever be allowed to interleave with.
    fileParallelism: false,
    reporters: ['default'],
  },
});
