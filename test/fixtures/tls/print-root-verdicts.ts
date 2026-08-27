import { fixtureAnchorsInRuntimeBundle, fixtureVerdicts } from './root-verdicts.ts';
import type { CrossRuntimeReport } from './root-verdicts.ts';

/**
 * Entry point for the cross-runtime half of `test/net-root-bundle.test.ts`:
 * run under `bun`, it prints the same JSON the test computes under Node
 * (ADR-0031). A separate file from `root-verdicts.ts` because that module is
 * imported by the test itself, and a module that prints on import would
 * scribble over the test reporter's output.
 *
 * One line, because the test reads it back off stdout.
 */
const report: CrossRuntimeReport = {
  verdicts: fixtureVerdicts(),
  anchorsInRuntimeBundle: fixtureAnchorsInRuntimeBundle(),
};

console.log(JSON.stringify(report));
