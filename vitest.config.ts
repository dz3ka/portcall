import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // The guardrail suite spawns the CLI and diffs filesystem inventories,
    // which is slower than a unit test and must not be raced.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
    reporters: ['default'],
  },
});
