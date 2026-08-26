import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // The default suite must run to completion on a machine with nothing
    // installed - a customer's laptop, a fresh clone, a reviewer's checkout.
    // The hostile-network suite under test/integration needs Docker, so it is
    // excluded here and run by `npm run test:integration` instead (ADR-0025).
    // Leaving it in with a conditional skip would put a permanently-skipped
    // test in the default run, which CLAUDE.md does not allow a milestone to
    // close with, and would report green where nothing ran.
    exclude: [...configDefaults.exclude, 'test/integration/**'],
    // The guardrail suite spawns the CLI and diffs filesystem inventories,
    // which is slower than a unit test and must not be raced.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
    reporters: ['default'],
  },
});
