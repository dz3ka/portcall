import { PUBLIC_ROOT_CA_PEMS } from '../../../src/net/root-bundle.ts';
import { fingerprintsOf } from './root-fingerprints.ts';

/**
 * Entry point for the cross-runtime half of `test/net-root-bundle.test.ts`:
 * run under `bun`, it prints the same JSON the test computes under Node. A
 * separate file from `root-fingerprints.ts` because that module is imported
 * by the test itself, and a module that prints on import would scribble over
 * the test reporter's output.
 */
console.log(JSON.stringify(fingerprintsOf(PUBLIC_ROOT_CA_PEMS)));
