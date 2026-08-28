import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { derToPem } from '../../../../src/net/pem.ts';
import { syntheticCert } from '../../../helpers/synthetic-chain.ts';

/**
 * Builds the committed runtime-store discovery tree.
 *
 *     node test/fixtures/truststore/runtime/make-tree.ts
 *
 * Run **manually**, never imported by a test - the rule
 * `test/fixtures/truststore/record-stores.ts` states: a module that writes on
 * import rewrites its own fixtures every time the suite runs.
 *
 * ## What the fixture is, and what it is not
 *
 * It is a **layout**. `src/net/runtime-stores.ts` answers "where would this
 * runtime look, and what is actually there", so the thing under test is the
 * shape of a virtualenv, a JDK 9+ tree, a JDK 8 tree and an `SSL_CERT_DIR` -
 * directory shapes, which is exactly what a committed tree can pin and an
 * in-process temp dir cannot show a reader of the repo.
 *
 * It is **not a recording**. Nothing here was copied off a machine. The PEM
 * bodies are self-signed certificates minted by this repo's own
 * `syntheticCert` helper under a throwaway key, with DNs that say so; the
 * `cacerts` files are ASCII placeholders and deliberately not keystores,
 * because WP3 only *locates* a keystore (it returns `unsupported-format` until
 * the reader lands) and a hand-authored keystore would be the guess-committed-
 * as-a-fixture that `record-stores.ts` forbids.
 *
 * No private key is written by this script or committed beside it. Portcall
 * never reads one (SPEC.md 4.2), so its fixtures do not contain one either.
 *
 * Regenerating rewrites every PEM (a fresh serial and a fresh key), so only run
 * it when the *layout* changes; the tests assert paths and counts, never a
 * specific certificate.
 */

const ROOT = import.meta.dirname;

const PLACEHOLDER_KEYSTORE = 'portcall fixture: a located, unparsed Java store. Not a keystore.\n';

/** One self-signed anchor, PEM, named so a stray copy is obviously synthetic. */
async function anchor(name: string): Promise<string> {
  return derToPem(await syntheticCert({ subject: `CN=Portcall Synthetic ${name}` }));
}

function write(relative: string, contents: string): void {
  const full = join(ROOT, relative);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents);
  console.log(`wrote ${relative}`);
}

// A posix virtualenv, and the Windows one, which puts site-packages under `Lib`.
write('virtualenv/lib/python3.12/site-packages/certifi/cacert.pem', await anchor('Certifi Venv Root'));
write('virtualenv-win/Lib/site-packages/certifi/cacert.pem', await anchor('Certifi Venv Root Win'));

// A per-user certifi, found by glob under HOME rather than by an env var.
write('home/.local/lib/python3.13/site-packages/certifi/cacert.pem', await anchor('Certifi User Root'));

// JDK 9+ and JDK 8 layouts. Located, never opened, until the keystore reader lands.
write('java-home-9/lib/security/cacerts', PLACEHOLDER_KEYSTORE);
write('java-home-8/jre/lib/security/cacerts', PLACEHOLDER_KEYSTORE);

// An `SSL_CERT_DIR` as OpenSSL lays one out: `.pem` and `.crt` are certificates,
// anything else in the directory is not and must be left alone.
write('ssl-cert-dir/one-root.pem', await anchor('Cert Dir Root One'));
write('ssl-cert-dir/two-root.crt', await anchor('Cert Dir Root Two'));
write('ssl-cert-dir/notes.txt', 'portcall fixture: not a certificate, and not to be read.\n');

// A single-file bundle, for the env vars that name one.
write('extra-ca.pem', `${await anchor('Extra CA Root')}${await anchor('Extra CA Root Two')}`);
