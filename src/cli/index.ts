#!/usr/bin/env node
import process from 'node:process';
import { main } from './main.ts';
import { EXIT } from './exit-codes.ts';
import { TOOL_NAME } from '../version.ts';

/**
 * Bootstrap only.
 *
 * All logic lives in `main.ts` so that tests can call `main(argv, streams)`
 * directly without a module deciding, on import, that it is the entrypoint.
 * "Am I the entrypoint" is answered differently by Node, by Bun and by a
 * `bun build --compile` binary; this layout means nothing has to answer it.
 */
main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const reason = error instanceof Error ? (error.stack ?? error.message) : String(error);
    process.stderr.write(`${TOOL_NAME}: internal error\n${reason}\n`);
    process.exitCode = EXIT.TOOL_ERROR;
  });
