import { isFormat, type Format } from '../report/index.ts';

/**
 * Hand-rolled argument parsing.
 *
 * No dependency, because every dependency is a line item in the security
 * review that decides whether this binary gets to run at all, and argv parsing
 * is not where that budget should go.
 *
 * Parsing is pure: it takes `argv` and returns a value. Nothing here touches
 * the filesystem, the network or `process`, so the whole CLI surface is
 * testable without spawning anything.
 */

export interface CheckCommand {
  kind: 'check';
  profile: string;
  format: Format;
  redact: boolean;
  timeoutMs: number;
  out?: string;
}

export type Command =
  | CheckCommand
  | { kind: 'profiles' }
  | { kind: 'help' }
  | { kind: 'version' };

export type ParseResult =
  | { ok: true; command: Command }
  | { ok: false; error: string };

export const DEFAULT_TIMEOUT_SECONDS = 60;
const MAX_TIMEOUT_SECONDS = 3600;

function fail(error: string): ParseResult {
  return { ok: false, error };
}

export function parseArgs(argv: readonly string[]): ParseResult {
  const args = [...argv];

  if (args.length === 0) return { ok: true, command: { kind: 'help' } };

  const first = args[0];
  if (first === '-h' || first === '--help' || first === 'help') {
    return { ok: true, command: { kind: 'help' } };
  }
  if (first === '-v' || first === '--version' || first === 'version') {
    return { ok: true, command: { kind: 'version' } };
  }
  if (first === 'profiles') {
    if (args.length > 1) return fail(`unexpected argument '${String(args[1])}' after 'profiles'`);
    return { ok: true, command: { kind: 'profiles' } };
  }
  if (first !== 'check') {
    return fail(`unknown command '${String(first)}'. Try: portcall check --profile <name>`);
  }

  let profile: string | undefined;
  let format: Format = 'text';
  let redact = true;
  let timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
  let out: string | undefined;

  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) continue;

    // `--help` is accepted anywhere, because a confused operator types it anywhere.
    if (arg === '-h' || arg === '--help') return { ok: true, command: { kind: 'help' } };

    if (arg === '--no-redact') {
      redact = false;
      continue;
    }

    const [flag, inlineValue] = splitFlag(arg);

    switch (flag) {
      case '--profile': {
        const value = inlineValue ?? args[++index];
        if (value === undefined || value.startsWith('-')) return fail('--profile needs a value');
        profile = value;
        break;
      }
      case '--format': {
        const value = inlineValue ?? args[++index];
        if (value === undefined || value.startsWith('-')) return fail('--format needs a value');
        if (!isFormat(value)) return fail(`unknown format '${value}'. Use json, html or text.`);
        format = value;
        break;
      }
      case '--out': {
        const value = inlineValue ?? args[++index];
        if (value === undefined || value.startsWith('-')) return fail('--out needs a value');
        out = value;
        break;
      }
      case '--timeout': {
        const value = inlineValue ?? args[++index];
        if (value === undefined || value.startsWith('-')) return fail('--timeout needs a value');
        const parsed = Number(value);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          return fail(`--timeout must be a positive number of seconds, got '${value}'`);
        }
        if (parsed > MAX_TIMEOUT_SECONDS) {
          return fail(`--timeout must be at most ${String(MAX_TIMEOUT_SECONDS)} seconds`);
        }
        timeoutSeconds = parsed;
        break;
      }
      default:
        return fail(`unknown option '${arg}'. Try: portcall --help`);
    }
  }

  if (profile === undefined) {
    return fail('check requires --profile <name|path>. Try: portcall profiles');
  }

  const command: CheckCommand = {
    kind: 'check',
    profile,
    format,
    redact,
    timeoutMs: Math.round(timeoutSeconds * 1000),
  };
  if (out !== undefined) command.out = out;
  return { ok: true, command };
}

function splitFlag(arg: string): [string, string | undefined] {
  const equals = arg.indexOf('=');
  if (arg.startsWith('--') && equals > 2) {
    return [arg.slice(0, equals), arg.slice(equals + 1)];
  }
  return [arg, undefined];
}
