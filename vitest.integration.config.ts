import { defineConfig } from 'vitest/config';

/**
 * The hostile-network suite (SPEC.md §10, ADR-0025).
 *
 * A separate config, not a flag on the default one, because the two runs have
 * opposite requirements: the default suite must pass anywhere, and this one
 * must fail anywhere the harness is not. `npm run test:integration` is never
 * part of `npm test` or `npm run verify`; it is run inside the compose network
 * (`test/harness/README.md`) and by the `harness` job in CI.
 */
export default defineConfig({
  test: {
    include: ['test/integration/**/*.test.ts'],
    // A real handshake through a real proxy, and mitmproxy fetches the upstream
    // certificate before it signs its own. Slower than a unit test by an order
    // of magnitude; still nowhere near this ceiling, which is here so a hung
    // socket fails the run rather than hanging CI.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Zero, explicitly. A scenario that only passes on the second attempt is
    // reporting something real about the network, and retrying it here would
    // convert the most interesting failure this repo can produce into a flake
    // nobody looks at.
    retry: 0,
    // The scenarios set and restore `process.env` around the proxy probe, which
    // reads it directly. Parallel files would race that.
    fileParallelism: false,
    reporters: ['default'],
  },
});
