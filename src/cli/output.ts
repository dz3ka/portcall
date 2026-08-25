import { writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';

/**
 * `--out` is the only write this program performs, and SPEC.md 4.1 says no
 * writes outside the working directory. That is enforced here rather than
 * trusted: the resolved target must be inside `cwd`, so `--out ../../.bashrc`
 * or `--out /etc/hosts` is refused with an explanation rather than obeyed.
 */
export class OutputPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OutputPathError';
  }
}

export function resolveOutputPath(target: string, cwd: string): string {
  const resolved = resolve(cwd, target);
  const rel = relative(cwd, resolved);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
    throw new OutputPathError(
      `refusing to write to '${target}': portcall does not write outside the ` +
        `working directory. Pass a path inside ${cwd}, or drop --out and redirect stdout.`,
    );
  }
  return resolved;
}

export async function writeReport(target: string, cwd: string, contents: string): Promise<string> {
  const resolved = resolveOutputPath(target, cwd);
  await writeFile(resolved, contents, { encoding: 'utf8' });
  return resolved;
}
