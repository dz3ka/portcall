import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { OS_TRUSTSTORE_COMMANDS } from '../../../src/net/os-truststore.ts';
import type { TrustStoreCommand } from '../../../src/net/types.ts';

/**
 * Records what each platform's own certificate-listing command actually prints.
 *
 *     node test/fixtures/truststore/record-stores.ts
 *
 * Run **manually**, or by a CI job on the platform being recorded - never
 * imported by a test, for the reason `test/fixtures/tls/record-chains.ts` gives:
 * a module that writes files on import would rewrite the fixtures every time the
 * suite ran, which is the one thing a committed fixture must not do.
 *
 * ## Why this file exists
 *
 * `src/net/os-truststore.ts`'s `pem-stream` branch is written against Apple's
 * *documentation* for `security find-certificate -a -p`. Nobody on this project
 * has ever executed that command: the Windows reader was measured (41 roots,
 * ~0.9 s, one unwrapped base64 DER per line), the macOS one was not. The plan's
 * rule is that a paid or irreversible gate may not be its own first
 * measurement, so the shape gets recorded from a real runner **before** the
 * parser is trusted - and a hand-authored "macOS fixture" is forbidden outright,
 * because a guess that has been committed as a fixture stops looking like a
 * guess.
 *
 * ## What it writes
 *
 * One raw capture per store, under `<platform>/<kind>.txt`, plus a
 * `<platform>/<kind>.json` recording how the capture was produced: the exact
 * `file` and `argv` from the pinned table (ADR-0033), the exit code, and the
 * byte and line counts. Bytes are written exactly as the child emitted them -
 * no re-wrapping, no newline translation - because the shape *is* the
 * measurement.
 *
 * ## What it does not write
 *
 * Nothing for a platform it is not running on. The table is filtered by
 * `process.platform`, so running this on Windows cannot produce a macOS fixture.
 *
 * ## Is it safe to commit the output?
 *
 * The captures are public trust anchors: root CA certificates, the same ones
 * every browser ships. They contain no key material - `find-certificate` has no
 * key-emitting mode and the machine `Root` store holds none - and no personal
 * store is read. A capture from a corporate machine will, however, name that
 * company's internal CA, so record on a clean CI runner, not on a customer's
 * laptop.
 */

const OUT_ROOT = import.meta.dirname;

/** A recording is only meaningful if the child was allowed to finish. */
const RECORD_TIMEOUT_MS = 60_000;

interface Capture {
  stdout: string;
  exit: number | null;
  signal: NodeJS.Signals | null;
  stderrBytes: number;
}

function capture(command: TrustStoreCommand): Promise<Capture> {
  return new Promise<Capture>((resolve, reject) => {
    const child = spawn(command.file, [...command.argv], {
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks: Buffer[] = [];
    let stderrBytes = 0;
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, RECORD_TIMEOUT_MS);
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length;
    });
    child.on('error', (error: Error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (exit: number | null, signal: NodeJS.Signals | null) => {
      clearTimeout(timer);
      resolve({ stdout: Buffer.concat(chunks).toString('utf8'), exit, signal, stderrBytes });
    });
  });
}

const commands = OS_TRUSTSTORE_COMMANDS.filter((command) => command.platform === process.platform);
if (commands.length === 0) {
  console.log(`No pinned trust-store command for ${process.platform}; nothing to record.`);
} else {
  const dir = join(OUT_ROOT, process.platform);
  mkdirSync(dir, { recursive: true });
  for (const command of commands) {
    const result = await capture(command);
    const lines = result.stdout.split(/\r?\n/).filter((line) => line.length > 0);
    writeFileSync(join(dir, `${command.kind}.txt`), result.stdout, 'utf8');
    writeFileSync(
      join(dir, `${command.kind}.json`),
      `${JSON.stringify(
        {
          recordedAt: new Date().toISOString(),
          platform: process.platform,
          kind: command.kind,
          format: command.format,
          file: command.file,
          locator: command.locator,
          argv: command.argv,
          exit: result.exit,
          signal: result.signal,
          stdoutBytes: result.stdout.length,
          stdoutLines: lines.length,
          stderrBytes: result.stderrBytes,
          longestLine: lines.reduce((longest, line) => Math.max(longest, line.length), 0),
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    console.log(
      `${command.kind}: exit=${String(result.exit)} bytes=${String(result.stdout.length)} lines=${String(lines.length)}`,
    );
  }
}
