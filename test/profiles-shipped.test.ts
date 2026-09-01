import { describe, expect, it } from 'vitest';
import { BUILTIN_PROFILE_SOURCES } from '../src/profiles/builtin.generated.ts';
import { builtinProfileIds, parseProfile } from '../src/profiles/loader.ts';

/**
 * The shipped profiles, checked as product surface rather than as fixtures.
 *
 * `npm run profiles:check` compares the generated file against a regeneration
 * of it — text against text. It proves the embed is *fresh*; it says nothing
 * about whether a profile is *valid*. A `cursor.yaml` carrying a key the
 * `.strict()` schema rejects embeds perfectly cleanly, ships, and first fails
 * as a `ProfileError` → exit 3 on a customer's laptop, on the one afternoon
 * the tool was supposed to save (ADR-0044).
 *
 * These two assertions close that gap and nothing more. Re-reading
 * `profiles/` from disk here would only re-prove what `profiles:check`
 * already proves, so this file reads only what the binary would carry.
 */
describe('shipped profiles', () => {
  it('parses every embedded profile through the strict schema', () => {
    for (const [id, text] of Object.entries(BUILTIN_PROFILE_SOURCES)) {
      // parseProfile throws a ProfileError naming the id and the failing
      // path, so letting it propagate reports better than any wrapper would.
      const loaded = parseProfile(id, 'builtin', text);
      expect(loaded.id).toBe(id);
      expect(loaded.source).toBe('builtin');
      expect(loaded.profile.endpoints.length).toBeGreaterThan(0);
    }
  });

  it('ships exactly three profiles, under exactly these public ids', () => {
    // A profile's filename stem *is* its `--profile` argument — there is no
    // alias layer (ADR-0043). Sorted, so the assertion cannot depend on a
    // filesystem's directory order across the three CI runners.
    expect([...builtinProfileIds()].sort()).toEqual([
      'claude-code',
      'cursor',
      'generic-ai-tool',
    ]);
  });
});
