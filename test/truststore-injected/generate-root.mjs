#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { syntheticCert } from '../helpers/synthetic-chain.ts';
import { derToPem } from '../../src/net/pem.ts';

/**
 * The three-OS proof's throwaway root (M4, WP7).
 *
 * A CI *step*, not a vitest file: it runs once, before the OS is asked to
 * trust anything, and its whole job is to hand the workflow a certificate to
 * inject and the workflow's own `PORTCALL_TEST_ROOT_SHA256` to later prove
 * that injection actually happened.
 *
 * Built through `test/helpers/synthetic-chain.ts` - the same in-process P-256
 * generator the fixture-driven suites already use - so this needs no
 * `openssl` on the runner and no vendored key checked into the repo. The root
 * is self-signed (an issuer that defaults to its own subject) because that is
 * the only shape a machine trust store actually holds an *anchor* as.
 *
 * `root.pem` is what `test/truststore-injected/injected-root.test.ts` and the
 * ubuntu/macOS injection commands read (`update-ca-certificates` and
 * `security add-trusted-cert` both accept PEM). `root.cer` is the same bytes
 * as raw DER, because Windows' `Import-Certificate` expects a `.cer`/`.crt`
 * file and does not unwrap PEM armour itself.
 *
 * Output convention: the certificate's SHA-256 is printed to **stdout as the
 * single line** `PORTCALL_TEST_ROOT_SHA256=<hash>`, and nothing else goes to
 * stdout - the workflow step redirects stdout straight into `$GITHUB_ENV`
 * (`node generate-root.mjs "$dir" >> "$GITHUB_ENV"`), which requires the file
 * to contain exactly that `KEY=value` line and nothing else. Every other
 * message this script has goes to stderr, where it lands in the job log
 * without corrupting the env file.
 */

const outDir = process.argv[2];
if (outDir === undefined || outDir.trim() === '') {
  console.error('usage: generate-root.mjs <output-directory>');
  process.exit(1);
}

const SUBJECT = 'CN=Portcall M4 Injected Test Root, O=Portcall CI';

const der = await syntheticCert({
  subject: SUBJECT,
  // Wide enough that no CI run ever sees this root expire mid-suite; narrow
  // dates are what the `tls` evaluation tests are for, not this one.
  notBefore: new Date('2020-01-01T00:00:00Z'),
  notAfter: new Date('2035-01-01T00:00:00Z'),
});

const sha256 = createHash('sha256').update(der).digest('hex');

await mkdir(outDir, { recursive: true });
const pemPath = join(outDir, 'root.pem');
const cerPath = join(outDir, 'root.cer');
await writeFile(pemPath, derToPem(der), 'utf8');
await writeFile(cerPath, Buffer.from(der));

console.error(`generate-root: wrote ${pemPath} and ${cerPath}`);
console.error(`generate-root: subject = ${SUBJECT}`);
console.error(`generate-root: sha256  = ${sha256}`);

// The one line the workflow step captures.
console.log(`PORTCALL_TEST_ROOT_SHA256=${sha256}`);
