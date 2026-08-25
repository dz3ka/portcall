#!/usr/bin/env node
// Generates src/profiles/builtin.generated.ts from profiles/*.yaml.
//
// The release artifact is a single self-contained executable (SPEC.md 5), so a
// built-in profile cannot be read from disk at runtime - there is no `profiles/`
// directory next to the binary. Embedding the YAML text (rather than parsed
// objects) keeps `profiles/` the single source of truth and keeps the loader
// identical for built-in and `--profile ./file.yaml` input.
//
// `--check` fails if the committed file is stale, so CI catches a profile PR
// that forgot to regenerate.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const profilesDir = join(root, 'profiles');
const target = join(root, 'src', 'profiles', 'builtin.generated.ts');

const files = readdirSync(profilesDir)
  .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
  .sort();

if (files.length === 0) {
  console.error('no profiles found in profiles/');
  process.exit(1);
}

const entries = files.map((file) => {
  const id = basename(file).replace(/\.ya?ml$/, '');
  const text = readFileSync(join(profilesDir, file), 'utf8').replace(/\r\n/g, '\n');
  return `  ${JSON.stringify(id)}: ${JSON.stringify(text)},`;
});

const output = `// GENERATED FILE - do not edit.
// Regenerate with \`npm run profiles:embed\`. Source of truth: profiles/*.yaml.
// CI runs \`npm run profiles:check\` and fails if this file is stale.

export const BUILTIN_PROFILE_SOURCES: Readonly<Record<string, string>> = Object.freeze({
${entries.join('\n')}
});

export const BUILTIN_PROFILE_IDS: readonly string[] = Object.freeze(
  Object.keys(BUILTIN_PROFILE_SOURCES),
);
`;

if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(target, 'utf8').replace(/\r\n/g, '\n');
  } catch {
    console.error(`missing ${target}; run: npm run profiles:embed`);
    process.exit(1);
  }
  if (current !== output) {
    console.error('src/profiles/builtin.generated.ts is stale; run: npm run profiles:embed');
    process.exit(1);
  }
  console.log(`profiles up to date (${files.length})`);
} else {
  writeFileSync(target, output, 'utf8');
  console.log(`embedded ${files.length} profile(s) -> src/profiles/builtin.generated.ts`);
}
