import { z } from 'zod';

/**
 * Profile schema (SPEC.md 6, ADR-0003).
 *
 * Profiles are data, not code: adding a vendor is a PR against `profiles/`,
 * not a release. That only holds if the schema is strict enough that a
 * malformed profile fails loudly at load time rather than silently skipping
 * an endpoint the customer actually needed checked.
 */

const HOSTNAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export const RUNTIMES = ['node', 'python', 'java', 'go'] as const;
export type Runtime = (typeof RUNTIMES)[number];

export const TLS_VERSIONS = ['1.0', '1.1', '1.2', '1.3'] as const;

export const endpointSchema = z
  .object({
    host: z.string().regex(HOSTNAME, 'must be a valid hostname'),
    port: z.number().int().min(1).max(65535),
    purpose: z.string().min(1),
    required: z.boolean().default(true),
    expect_streaming: z.boolean().default(false),
  })
  .strict();

export const profileSchema = z
  .object({
    name: z.string().min(1),
    endpoints: z.array(endpointSchema).min(1),
    runtimes: z.array(z.enum(RUNTIMES)).min(1),
    tls: z
      .object({
        min_version: z.enum(TLS_VERSIONS),
        interception_tolerated: z.boolean(),
      })
      .strict()
      .default({ min_version: '1.2', interception_tolerated: true }),
  })
  .strict();

export type Endpoint = z.output<typeof endpointSchema>;
export type Profile = z.output<typeof profileSchema>;

/** A loaded profile plus where it came from, for the report header. */
export interface LoadedProfile {
  id: string;
  source: 'builtin' | 'file';
  profile: Profile;
}
