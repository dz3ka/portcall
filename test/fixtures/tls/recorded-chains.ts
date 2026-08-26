import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

/**
 * The recorded certificate chains SPEC.md §10 asks for, read back off disk.
 *
 * SPEC.md §10 names four fixture conditions - public, intercepted, expired,
 * wrong-SNI - and CLAUDE.md's testing rule is that every parser is driven from
 * committed fixtures. `test/helpers/synthetic-chain.ts` mints chains in
 * process, which is the right tool for the dimension sweeps in
 * `test/tls-evaluate.test.ts` but leaves nothing in the repo a reader can
 * point at. These files are that committed material: base64-DER inside JSON
 * (design decision D6), one file per condition, recorded by
 * `record-chains.ts` next door.
 *
 * A file is one *observation of an endpoint*, not one certificate: it carries
 * the direct capture and, for the intercepted condition, the capture taken
 * through the proxy as well, because "the proxied path presents a different
 * leaf" is a claim about a pair. That shape is what lets
 * `test/tls-recorded-chains.test.ts` replay a fixture straight through the
 * probe rather than through the evaluation alone.
 *
 * `capturedAt` travels with the chain because the expiry verdicts are a
 * function of a clock: the fixture records when the capture was taken, the
 * test injects that instant as `now`, and an expired certificate stays expired
 * rather than becoming a certificate that expired longer ago every day.
 *
 * Parsed with zod rather than cast, following `src/profiles/loader.ts`: these
 * are files on disk, a hand edit can malform them, and "chainDer[0] is
 * undefined" three frames deep is a worse failure than the field that is wrong.
 */

/** The four conditions SPEC.md §10 names. The file name is the condition. */
export const RECORDED_CONDITIONS = ['public', 'intercepted', 'expired', 'wrong-sni'] as const;

export type RecordedCondition = (typeof RECORDED_CONDITIONS)[number];

const captureSchema = z
  .object({
    negotiatedProtocol: z.string().nullable(),
    negotiatedCipher: z.string().nullable(),
    /** The SNI actually sent, so a name mismatch is reproducible without a socket. */
    requestedSni: z.string(),
    /** Leaf first, one base64-encoded DER certificate per element. */
    chainDer: z.array(z.string().min(1)).min(1),
  })
  .strict();

const recordedChainSchema = z
  .object({
    condition: z.enum(RECORDED_CONDITIONS),
    summary: z.string().min(1),
    capturedAt: z.string().datetime(),
    host: z.string().min(1),
    /** Subject of the bundled public root this chain is anchored in, or null when it is privately rooted. */
    publicAnchor: z.string().min(1).nullable(),
    direct: captureSchema,
    /** Present only for the intercepted condition: the same endpoint, seen through a proxy. */
    viaProxy: captureSchema.optional(),
  })
  .strict();

export interface RecordedCapture {
  negotiatedProtocol: string | null;
  negotiatedCipher: string | null;
  requestedSni: string;
  chainDer: Uint8Array[];
}

export interface RecordedChain {
  condition: RecordedCondition;
  summary: string;
  capturedAt: Date;
  host: string;
  publicAnchor: string | null;
  direct: RecordedCapture;
  viaProxy: RecordedCapture | null;
}

const CHAIN_DIR = join(import.meta.dirname, 'chains');

/** Where a condition's fixture lives. Exported so a failure message can name the file to re-record. */
export function recordedChainPath(condition: RecordedCondition): string {
  return join(CHAIN_DIR, `${condition}.json`);
}

function decode(capture: z.output<typeof captureSchema>): RecordedCapture {
  return { ...capture, chainDer: capture.chainDer.map((der) => new Uint8Array(Buffer.from(der, 'base64'))) };
}

/** One recorded observation, with the DER decoded back to the bytes a capture would carry. */
export function loadRecordedChain(condition: RecordedCondition): RecordedChain {
  const path = recordedChainPath(condition);
  const parsed = recordedChainSchema.safeParse(JSON.parse(readFileSync(path, 'utf8')));
  if (!parsed.success) {
    throw new Error(`${path} is not a recorded chain: ${parsed.error.issues.map((issue) => `${issue.path.join('.')} ${issue.message}`).join('; ')}`);
  }
  const file = parsed.data;
  return {
    ...file,
    capturedAt: new Date(file.capturedAt),
    direct: decode(file.direct),
    viaProxy: file.viaProxy === undefined ? null : decode(file.viaProxy),
  };
}
