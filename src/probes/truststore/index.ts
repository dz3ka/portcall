import type { Probe, ProbeContext } from '../../engine/index.ts';
import type { Finding } from '../../model/finding.ts';
import { OS_TRUSTSTORE_COMMANDS, osTrustStoreReader } from '../../net/os-truststore.ts';
import { PUBLIC_ROOT_CA_PEMS } from '../../net/root-bundle.ts';
import { MAX_RUNTIME_STORE_BYTES, runtimeStoreReader } from '../../net/runtime-stores.ts';
import type { OsTrustStoreReader, RuntimeStoreReader } from '../../net/types.ts';
import { crossCheck } from './evaluate.ts';

/**
 * The `truststore` probe (M4, SPEC.md §7): does this machine trust roots the
 * runtimes running on it do not, and is one of them the anchor the `tls` probe
 * just watched terminate a chain.
 *
 * This file is the *edge*, and nothing else. It reads two stores through the
 * seams in `net/` and hands what came back to `evaluate.ts`, which decides
 * everything and is fixture-tested without a process or a file
 * (`test/guardrails/x509-parse-only.test.ts` bans every `node:` import in this
 * directory, so the readers and the environment can only arrive as
 * parameters).
 *
 * Registered **last**, after `tls`: the cross-check reads
 * `context.observedAnchors`, which `tls` fills in as it captures chains
 * (ADR-0034), and the report then reads as "here is the chain the network
 * presented, and here is whether your runtimes trust it".
 *
 * The reader is handed `context.deadline`, not a timeout of its own. The
 * per-store budget belongs to the pinned table row and the run belongs to the
 * run (ADR-0037), so there is no number here for a test to drift apart from -
 * and the same table's `timeoutMs` column travels into the evaluation, which
 * needs it to tell a store that outran its own ceiling from one the run's clock
 * cut short.
 */

export const truststoreProbe: Probe = {
  name: 'truststore',
  run(context: ProbeContext): Promise<Finding[]> {
    return runTruststore(context);
  },
};

export async function runTruststore(
  context: ProbeContext,
  osReader: OsTrustStoreReader = osTrustStoreReader,
  runtimeReader: RuntimeStoreReader = runtimeStoreReader,
  publicRootPems: readonly string[] = PUBLIC_ROOT_CA_PEMS,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): Promise<Finding[]> {
  const runtimes = context.profile.profile.runtimes;

  // Serial, not concurrent, and the order is the reader's own: the OS read is
  // the one with a budget carved out of the run's remaining time, so letting a
  // fan-out of file reads share that window would shorten it for no gain -
  // there are a handful of small reads on the other side.
  const osStores = await osReader.read({ signal: context.signal, deadline: context.deadline });
  const runtimeStores = await runtimeReader.read(runtimes, { env, platform, maxBytes: MAX_RUNTIME_STORE_BYTES });

  return crossCheck({
    platform,
    osStores,
    runtimeStores,
    runtimes,
    publicRootPems,
    observedAnchors: context.observedAnchors,
    osCommands: OS_TRUSTSTORE_COMMANDS,
  });
}
