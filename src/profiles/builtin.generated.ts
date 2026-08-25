// GENERATED FILE - do not edit.
// Regenerate with `npm run profiles:embed`. Source of truth: profiles/*.yaml.
// CI runs `npm run profiles:check` and fails if this file is stale.

export const BUILTIN_PROFILE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
  "generic-ai-tool": "# A deliberately minimal profile: the endpoints almost any AI developer tool\n# needs, and nothing vendor-specific. Named profiles for individual vendors are\n# separate files, added by PR rather than by release (ADR-0003).\nname: Generic AI developer tool\nendpoints:\n  - host: api.anthropic.com\n    port: 443\n    purpose: model inference\n    required: true\n    expect_streaming: true\n  - host: registry.npmjs.org\n    port: 443\n    purpose: extension updates\n    required: false\nruntimes: [node]           # which trust stores to cross-check\ntls:\n  min_version: \"1.2\"\n  interception_tolerated: true   # some tools work fine behind a re-signing proxy\n",
});

export const BUILTIN_PROFILE_IDS: readonly string[] = Object.freeze(
  Object.keys(BUILTIN_PROFILE_SOURCES),
);
