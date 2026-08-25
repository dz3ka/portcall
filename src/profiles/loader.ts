import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';
import { profileSchema, type LoadedProfile } from './schema.ts';
import { BUILTIN_PROFILE_IDS, BUILTIN_PROFILE_SOURCES } from './builtin.generated.ts';

export class ProfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProfileError';
  }
}

export function builtinProfileIds(): readonly string[] {
  return BUILTIN_PROFILE_IDS;
}

/**
 * Parse and validate profile YAML. Pure: takes text, returns a profile or
 * throws. All disk access lives in `loadProfile` so this is fixture-testable.
 */
export function parseProfile(id: string, source: 'builtin' | 'file', text: string): LoadedProfile {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (error) {
    throw new ProfileError(
      `profile '${id}' is not valid YAML: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const result = profileSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new ProfileError(`profile '${id}' failed validation:\n${issues}`);
  }

  const duplicates = findDuplicateEndpoints(result.data.endpoints);
  if (duplicates.length > 0) {
    throw new ProfileError(
      `profile '${id}' declares duplicate endpoints: ${duplicates.join(', ')}`,
    );
  }

  return { id, source, profile: result.data };
}

function findDuplicateEndpoints(endpoints: readonly { host: string; port: number }[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const endpoint of endpoints) {
    const key = `${endpoint.host.toLowerCase()}:${endpoint.port}`;
    if (seen.has(key)) duplicates.add(key);
    seen.add(key);
  }
  return [...duplicates].sort();
}

/**
 * Resolve a `--profile` argument.
 *
 * A bare name is a built-in profile, embedded in the binary at build time. A
 * value containing a path separator or a YAML extension is read from disk, so
 * a customer can check a profile they wrote themselves without rebuilding.
 */
export async function loadProfile(id: string): Promise<LoadedProfile> {
  if (looksLikePath(id)) {
    let text: string;
    try {
      text = await readFile(id, 'utf8');
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new ProfileError(`cannot read profile file '${id}': ${reason}`);
    }
    return parseProfile(id, 'file', text);
  }

  const source = BUILTIN_PROFILE_SOURCES[id];
  if (source === undefined) {
    throw new ProfileError(
      `unknown profile '${id}'. Built-in profiles: ${BUILTIN_PROFILE_IDS.join(', ')}. ` +
        `To use your own, pass a path such as ./my-profile.yaml`,
    );
  }
  return parseProfile(id, 'builtin', source);
}

const WINDOWS_SEPARATOR = String.fromCharCode(92);

export function looksLikePath(id: string): boolean {
  return id.includes('/') || id.includes(WINDOWS_SEPARATOR) || /\.ya?ml$/i.test(id);
}
