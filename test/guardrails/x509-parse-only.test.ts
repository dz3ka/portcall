import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');
const TLS_PROBE_DIR = join(SRC_ROOT, 'probes', 'tls');

/**
 * ADR-0021: `@peculiar/x509` is in this repo to **parse DER and read fields**,
 * and for nothing else. Root membership is decided in exactly one place -
 * `src/probes/tls/public-roots.ts`, over the runtime's own bundle - and if the
 * evaluation ever reached for the library's chain-building or signature APIs
 * there would be two paths to the most alarming finding portcall emits, one
 * fixture-tested and one inside a dependency, free to disagree without anything
 * noticing.
 *
 * That constraint was prose in an ADR and nothing in the tree enforced it. It
 * is enforced here, as a guardrail test rather than an eslint rule, for the
 * reasons the rest of `test/guardrails/` exists: this is where the repo already
 * keeps its invariants, the failure message can explain *why* rather than name
 * a rule id, and a text scan needs no type information to see
 * `certificate.verify(...)` - which a lint rule would need `no-restricted-syntax`
 * plus a member-expression selector to approximate, and would still miss
 * through an alias.
 *
 * Like `no-network-outside-allowlist.test.ts`, this is a grep and it says so:
 * it catches the API names as written, not a call assembled at runtime. The
 * real guarantee is that the trust decision has one implementation and it is
 * fixture-tested; this stops the second one from being written by accident.
 */

interface Forbidden {
  pattern: RegExp;
  why: string;
}

const FORBIDDEN_TRUST_APIS: readonly Forbidden[] = [
  { pattern: /\bX509ChainBuilder\b/, why: 'builds a chain against its own trust anchors (ADR-0021)' },
  { pattern: /\.verify\s*\(/, why: 'verifies a signature; portcall reports what the bytes say (ADR-0021)' },
  { pattern: /\.validate\s*\(/, why: 'validates against a trust decision this repo makes elsewhere (ADR-0021)' },
  { pattern: /\bisSelfSigned\s*\(/, why: 'checks the self-signature, not the names; use a DN comparison (ADR-0021)' },
  { pattern: /\bcryptoProvider\b/, why: 'only signing and verification need a crypto provider (ADR-0021)' },
];

/**
 * The `tls` probe must also stay `node:*`-free: it is the pure half of the
 * split ADR-0002 describes, and the moment it imports a runtime module its
 * verdicts stop being reproducible from bytes alone. The networking guardrail
 * already bans `node:net`/`node:tls`/`node:dns` outside `src/net/`; this widens
 * it to *every* `node:` module for this directory.
 */
const NODE_IMPORT = /from\s+['"]node:[a-z/]+['"]|require\(\s*['"]node:[a-z/]+['"]\s*\)/;

/** Offenders in one file's source text. `rel` is POSIX-style, relative to `src/`. */
export function scanForTrustApiUse(rel: string, text: string): string[] {
  // Block comments are stripped first: ADR-0021's constraint is quoted in the
  // module comments of the very files this scans, and a guardrail that fails on
  // its own documentation teaches people to delete the documentation.
  const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  return FORBIDDEN_TRUST_APIS.filter(({ pattern }) => pattern.test(code)).map(
    ({ pattern, why }) => `${rel}: ${pattern.toString()} - ${why}`,
  );
}

export function scanForNodeImport(rel: string, text: string): string[] {
  return NODE_IMPORT.test(text) ? [`${rel}: imports a node: module, but this module must stay pure`] : [];
}

async function* walk(dir: string): AsyncGenerator<string> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full);
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      yield full;
    }
  }
}

async function tlsProbeSources(): Promise<{ rel: string; text: string }[]> {
  const files: { rel: string; text: string }[] = [];
  for await (const file of walk(TLS_PROBE_DIR)) {
    files.push({ rel: relative(SRC_ROOT, file).replace(/\\/g, '/'), text: await readFile(file, 'utf8') });
  }
  return files;
}

describe('x509 parse-only guardrail', () => {
  it('scans a tls probe that actually exists, so the checks below are not vacuous', async () => {
    const files = await tlsProbeSources();
    expect(files.map((file) => file.rel).sort()).toContain('probes/tls/evaluate.ts');
    expect(files.map((file) => file.rel).sort()).toContain('probes/tls/public-roots.ts');
  });

  it('no module in src/ calls an x509 trust or verification API', async () => {
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      offenders.push(...scanForTrustApiUse(rel, await readFile(file, 'utf8')));
    }
    expect(offenders).toEqual([]);
  });

  it('the tls probe imports no node: module, so its verdicts are reproducible from bytes', async () => {
    const offenders = (await tlsProbeSources()).flatMap((file) => scanForNodeImport(file.rel, file.text));
    expect(offenders).toEqual([]);
  });

  it.each([
    'const chain = await new X509ChainBuilder({ certificates: roots }).build(leaf);',
    'if (await certificate.verify({ signatureOnly: true })) return true;',
    'await chain.validate({ date: now });',
    'if (await root.isSelfSigned()) return true;',
    'cryptoProvider.set(crypto);',
  ])('catches %s', (source) => {
    expect(scanForTrustApiUse('probes/tls/evaluate.ts', source)).toHaveLength(1);
  });

  it('does not fail on the parsing and field reads that are allowed', () => {
    const allowed = [
      'const certificate = new X509Certificate(der);',
      'const names = certificate.subjectName.toJSON();',
      "const extension = certificate.getExtension('2.5.29.17');",
      'return certificate.notAfter.getTime() < now.getTime();',
    ].join('\n');
    expect(scanForTrustApiUse('probes/tls/evaluate.ts', allowed)).toEqual([]);
  });

  it('catches a node: import in the pure probe', () => {
    expect(scanForNodeImport('probes/tls/evaluate.ts', "import { createHash } from 'node:crypto';")).toHaveLength(1);
  });
});
