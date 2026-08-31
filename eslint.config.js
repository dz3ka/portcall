// @ts-check
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'build/**',
      'coverage/**',
      // Fixture PAC scripts (test/proxy-pac.test.ts): real, standalone
      // JavaScript text read as fixtures, not part of the tsconfig program -
      // one is deliberately syntactically invalid to prove error handling.
      'test/fixtures/pac/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // CLAUDE.md: no `any` in committed code. Not negotiable, so it is an error.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      eqeqeq: ['error', 'always'],
      'no-console': 'off',
    },
  },
  {
    // Build/CI scripts are plain ESM run by node directly; they are not part of
    // the typed program and do not ship in the binary. They still run on Node,
    // so `no-undef` needs Node's globals declared — `nodeBuiltin` and not `node`
    // because these are ESM and have no `require`/`__dirname`.
    files: [
      'scripts/**/*.mjs',
      // The three-OS proof's own root generator (M4, WP7): a CI step run
      // directly by `node`, same as the build scripts above, and not part of
      // the typed program for the same reason.
      'test/truststore-injected/generate-root.mjs',
      'eslint.config.js',
      'vitest.config.ts',
    ],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      // Merge, don't replace: `disableTypeChecked` sets parserOptions of its own
      // to detach these files from the typed program, and a bare override here
      // would silently re-attach them.
      ...tseslint.configs.disableTypeChecked.languageOptions,
      globals: globals.nodeBuiltin,
    },
  },
);
