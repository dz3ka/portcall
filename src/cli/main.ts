import process from 'node:process';
import { parseArgs, type CheckCommand } from './args.ts';
import { EXIT, exitCodeFor, type ExitCode } from './exit-codes.ts';
import { helpText } from './help.ts';
import { builtinProfileIds, loadProfile, ProfileError } from '../profiles/loader.ts';
import { run } from '../engine/index.ts';
import { redact } from '../redact/index.ts';
import { render } from '../report/index.ts';
import { writeReport, OutputPathError } from './output.ts';
import { TOOL_NAME, VERSION } from '../version.ts';

export interface Streams {
  out: (text: string) => void;
  err: (text: string) => void;
}

const stdio: Streams = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
};

export async function main(argv: readonly string[], streams: Streams = stdio): Promise<ExitCode> {
  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    streams.err(`${TOOL_NAME}: ${parsed.error}\n`);
    return EXIT.TOOL_ERROR;
  }

  switch (parsed.command.kind) {
    case 'help':
      streams.out(helpText());
      return EXIT.OK;
    case 'version':
      streams.out(`${TOOL_NAME} ${VERSION}\n`);
      return EXIT.OK;
    case 'profiles':
      for (const id of builtinProfileIds()) streams.out(`${id}\n`);
      return EXIT.OK;
    case 'check':
      return await check(parsed.command, streams);
  }
}

async function check(command: CheckCommand, streams: Streams): Promise<ExitCode> {
  let loaded;
  try {
    loaded = await loadProfile(command.profile);
  } catch (error) {
    if (error instanceof ProfileError) {
      streams.err(`${TOOL_NAME}: ${error.message}\n`);
      return EXIT.TOOL_ERROR;
    }
    throw error;
  }

  if (!command.redact) {
    streams.err(
      `${TOOL_NAME}: WARNING - redaction is disabled. This report may contain internal\n` +
        `  hostnames, IP addresses, usernames, filesystem paths and serial numbers.\n` +
        `  Do not send it outside the organisation that produced it.\n`,
    );
  }

  const { report } = await run({ profile: loaded, timeoutMs: command.timeoutMs });

  // The only path from a report to output. Renderers accept nothing else.
  const safe = redact(report, {
    enabled: command.redact,
    publicValues: loaded.profile.endpoints.map((endpoint) => endpoint.host),
  });

  const rendered = render(safe, command.format);

  if (command.out !== undefined) {
    try {
      const written = await writeReport(command.out, process.cwd(), rendered);
      streams.err(`${TOOL_NAME}: report written to ${written}\n`);
    } catch (error) {
      if (error instanceof OutputPathError) {
        streams.err(`${TOOL_NAME}: ${error.message}\n`);
        return EXIT.TOOL_ERROR;
      }
      const reason = error instanceof Error ? error.message : String(error);
      streams.err(`${TOOL_NAME}: could not write '${command.out}': ${reason}\n`);
      return EXIT.TOOL_ERROR;
    }
  } else {
    streams.out(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
  }

  return exitCodeFor(safe.summary.severity);
}
