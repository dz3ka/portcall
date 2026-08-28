import { describe, expect, it } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';

const SRC_ROOT = join(import.meta.dirname, '..', '..', 'src');

/**
 * SPEC.md 4.2 / CLAUDE.md non-negotiable: never read keychains, tokens,
 * private keys or browser profiles, and never prompt for a password. Static
 * text scan — this cannot prove absence of a clever obfuscation, but it is a
 * cheap trip-wire against the obvious mistake of a probe importing the wrong
 * thing to "just check whether a cert is trusted".
 */
const FORBIDDEN_PATTERNS: readonly RegExp[] = [
  // M4 (ADR-0033) narrowed two patterns here — `/keychain/i` and
  // `/security find-/i` — from "the word keychain" to the item classes SPEC.md
  // 4.2 actually forbids. The reason is that the `truststore` probe must
  // enumerate the machine's *public* trust anchors, and on macOS the only
  // shipped way to do that names a keychain file. Banning the word would have
  // banned the sanctioned read along with the forbidden ones.
  //
  // ADR-0025 forbids weakening a guardrail to buy a green run, so the
  // narrowing arrives with `subprocess-boundary.test.ts`, which pins the
  // complete argv of every process portcall may start and limits process
  // starts to one file. Net, the invariant is stronger: previously "no file
  // says keychain", now "no file names a personal credential store, a key, an
  // export or a keystore password, and here is the byte-pinned list of every
  // command that may run". The two calls that must stay legal — `security
  // find-certificate -a -p <system keychain>` and `readKeystore(bytes)` — are
  // asserted below to match nothing here, so the narrowing is deliberate
  // rather than accidental.
  //
  // The macOS user's own keychain and its container file.
  /login\.keychain/i,
  /keychain-db/i,
  // `security` subcommands that reach keys, identities or the whole store.
  /find-generic-password/i,
  /find-internet-password/i,
  /find-identity/i,
  /find-key\b/i,
  /export-keychain/i,
  /dump-keychain/i,
  /unlock-keychain/i,
  // Loose enough to see the argv-array shape (`'security', ['export'`) as
  // well as the shell-string one; a grep that only knew the shell form would
  // miss the way this repo actually spawns things.
  /\bsecurity\b[^\n]{0,24}\bexport\b/i,
  /-t['"\s,]{1,6}identities/i,
  // Windows personal certificate stores, and the shapes that export a key.
  // `\\+`, not `\\`: the scan reads TypeScript source, where the same path is
  // written `Cert:\\CurrentUser` inside a string literal and `Cert:\CurrentUser`
  // in a comment. Both must trip.
  /Cert:\\+CurrentUser/i,
  /Cert:\\+LocalMachine\\+My/i,
  /-store\s+My\b/,
  /HasPrivateKey/i,
  /X509ContentType/i,
  /\.pfx\b/i,
  // Keystore passwords. `pkcs12` is deliberately *not* a pattern: ADR-0036's
  // reader parses the PKCS#12 *container* by name and must be able to say so.
  // It is the password, not the container format, that 4.2 forbids touching,
  // and portcall supplies none — not even the published default.
  /storepass/i,
  /keypass/i,
  /id_rsa/i,
  /\.ssh(?:[/\\]|['"`])/i,
  /Login Data/,
  /cookies\.sqlite/i,
  /\breadline\b/i,
  /wincred/i,
  // SPEC.md 4 / CLAUDE.md: the proxy probe reports the auth scheme a proxy
  // demands (`Proxy-Authenticate`) but never authenticates - no code path may
  // construct a `Proxy-Authorization` or bare `Authorization` request header.
  /proxy-authorization/i,
  /['"`]?authorization['"`]?\s*:/i,
];

/**
 * `src/cli/help.ts` is required (SPEC.md 3, CLAUDE.md) to say plainly, in the
 * `--help` text, that portcall "never reads keychains, tokens, private keys
 * or browser profiles" — that is the negative disclosure the security team
 * reads, not an implementation. Flagging that sentence would be a false
 * positive against the exact promise this guardrail exists to hold the code
 * to, so it is the one allow-listed file, and only for that reason.
 */
const ALLOWLIST: ReadonlySet<string> = new Set(['cli/help.ts']);

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

describe('no credential access guardrail', () => {
  it('src/ contains none of the forbidden credential-access strings', async () => {
    const offenders: string[] = [];
    for await (const file of walk(SRC_ROOT)) {
      const rel = relative(SRC_ROOT, file).replace(/\\/g, '/');
      if (ALLOWLIST.has(rel)) continue;
      const text = await readFile(file, 'utf8');
      for (const pattern of FORBIDDEN_PATTERNS) {
        if (pattern.test(text)) offenders.push(`${rel}: matched ${pattern.toString()}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the allow-listed help.ts only contains the negative disclosure, not an import', async () => {
    const text = await readFile(join(SRC_ROOT, 'cli', 'help.ts'), 'utf8');
    expect(text).toContain('never reads keychains');
    expect(text).not.toMatch(/require\(|from\s+['"].*keychain/i);
  });

  it('the patterns actually trip on realistic offending code', () => {
    // Planted only in these strings, never in src/: proves the patterns fire on
    // the exact shapes the mistake would take, using the identical regex
    // objects (and `.test()` call) the real scan uses. The M4 narrowing
    // (ADR-0033) is only defensible if every one of these still trips, so each
    // pattern class added there has a line here.
    const offendingSnippets = [
      'headers["Proxy-Authorization"] = `Basic ${credentials}`;',
      "request.setHeader('proxy-authorization', digest);",
      'const headers = { authorization: `Bearer ${token}` };',
      "spawn('/usr/bin/security', ['find-generic-password', '-s', service, '-w']);",
      "spawn('/usr/bin/security', ['export', '-t', 'identities', '-k', keychainPath, '-o', out]);",
      "await readFile(join(home, 'Library/Keychains/login.keychain-db'));",
      "const argv = ['-Command', 'Get-ChildItem -Path Cert:\\\\CurrentUser\\\\My'];",
      "const argv = ['-Command', 'Get-ChildItem Cert:\\\\LocalMachine\\\\My | Where-Object HasPrivateKey'];",
      "spawn('certutil.exe', ['-exportPFX', 'My', thumbprint, 'out.pfx']);",
      "const blob = certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, password);",
      "spawn('keytool', ['-list', '-cacerts', '-storepass', 'changeit']);",
      "spawn('keytool', ['-importkeystore', '-srckeypass', secret]);",
    ];
    for (const snippet of offendingSnippets) {
      const matched = FORBIDDEN_PATTERNS.some((pattern) => pattern.test(snippet));
      expect(matched, `no pattern trips on: ${snippet}`).toBe(true);
    }
  });

  it('lets through the two reads SPEC.md 4.2 (as amended) sanctions', () => {
    // The other half of the narrowing, and the half a reviewer should read
    // hardest: enumerating public trust anchors, and parsing a keystore
    // container's bytes, are the operations the `truststore` probe exists to
    // perform (ADR-0032, ADR-0036). Neither reads a key and neither supplies a
    // password. If a future pattern here starts flagging one of these, the
    // probe is what breaks, so the constraint is written down as a test.
    const sanctioned = [
      "spawn('/usr/bin/security', ['find-certificate', '-a', '-p', '/Library/Keychains/System.keychain']);",
      'const anchors = readKeystore(bytes);',
    ];
    for (const snippet of sanctioned) {
      const matched = FORBIDDEN_PATTERNS.filter((pattern) => pattern.test(snippet)).map(String);
      expect(matched, `a sanctioned read is flagged: ${snippet}`).toEqual([]);
    }
  });
});
