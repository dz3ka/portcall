import type { Runtime } from '../profiles/schema.ts';
import type { NetworkGuard } from './guard.ts';

/**
 * The network seam (M1). Probes depend on these interfaces, never on a socket
 * API: the real implementations live under `src/net/`, which is the only place
 * the guardrail test lets `node:net`/`node:tls`/`node:dns` be imported. This
 * file is types only and imports nothing from `node:*`, so a probe module can
 * import it without tripping that scan.
 *
 * The `guard` travels in the options bag on every call rather than being
 * captured by a factory. An implementation that closed over a guard could be
 * built once and reused after the guard changed; passing it per call makes the
 * enforcement point visible at the call site, where the host and port are.
 */

export type AttemptPhase = 'dns' | 'connect' | 'tls' | 'http';

/** Per-phase elapsed time; `null` for a phase that was never reached. */
export interface AttemptTiming {
  dnsMs: number | null;
  connectMs: number | null;
  tlsMs: number | null;
  httpMs: number | null;
}

/**
 * The outcome of one endpoint attempt. Failure carries the phase it died in:
 * DNS, connect-refused, TLS and HTTP are four different teams and four
 * different tickets (CLAUDE.md), so they are never collapsed into one error.
 */
export type EndpointAttempt =
  | { ok: true; addresses: readonly string[]; tlsProtocol: string | null; status: number | null; timing: AttemptTiming }
  | {
      ok: false;
      phase: AttemptPhase;
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      addresses: readonly string[];
      status: number | null;
      timing: AttemptTiming;
    };

export interface EndpointTarget {
  host: string;
  port: number;
  useTls: boolean;
}

export interface AttemptOptions {
  signal: AbortSignal;
  guard: NetworkGuard;
  connectTimeoutMs: number;
  tlsTimeoutMs: number;
  httpTimeoutMs: number;
}

export interface EndpointProber {
  attempt(target: EndpointTarget, options: AttemptOptions): Promise<EndpointAttempt>;
}

export type DnsOutcome =
  | { ok: true; addresses: readonly string[]; elapsedMs: number }
  | { ok: false; code: string | null; abortedBy: 'phase-timeout' | 'run-signal' | null; elapsedMs: number };

export interface DnsResolver {
  resolve(host: string, options: { signal: AbortSignal; guard: NetworkGuard }): Promise<DnsOutcome>;
}

/**
 * The proxy seam (M2). `PacFetcher` fetches a PAC script over the same
 * phase-classified model as `EndpointAttempt`; `ProxyConnectAttempt` is the
 * outcome of one CONNECT attempt against a proxy, produced by
 * `connectDetailed` in `proxy-connect.ts` alongside the raw
 * `Proxy-Authenticate` header it never interprets (SPEC.md §4 — the probe
 * reports the scheme demanded and never authenticates).
 */
export type PacFetchOutcome =
  | { ok: true; script: string; elapsedMs: number }
  | {
      ok: false;
      phase: 'dns' | 'connect' | 'tls' | 'http';
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      elapsedMs: number;
    };

export interface PacFetcher {
  fetch(url: string, options: { signal: AbortSignal; guard: NetworkGuard; maxBytes: number }): Promise<PacFetchOutcome>;
}

export type AuthScheme = 'Basic' | 'NTLM' | 'Negotiate' | 'none' | 'unknown';

/**
 * No `authScheme` member: the scheme is not something this seam can know.
 * Classifying one means reading the raw `Proxy-Authenticate` header, which
 * travels on `ProxyConnectDetail` and is interpreted by
 * `probes/proxy/auth.ts` — the transport/judgment split every other seam in
 * this file keeps.
 */
export type ProxyConnectAttempt =
  | { ok: true; status: number; timing: AttemptTiming }
  | {
      ok: false;
      phase: AttemptPhase | 'tunnel';
      code: string | null;
      status: number | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
      timing: AttemptTiming;
    };

/**
 * The TLS capture seam (M3, ADR-0002). Capture and validation are two jobs:
 * this seam opens the connection with certificate verification *deliberately
 * off* and hands back the presented chain as raw DER, and a pure function over
 * those bytes decides what the chain means. Nothing here interprets a
 * certificate, and nothing downstream reads a runtime certificate object -
 * that is what makes "the verdict is identical under Bun and Node" a testable
 * claim rather than a hope.
 *
 * `TunnelOutcome` is deliberately *not* here: it carries a live `net.Socket`,
 * and this file imports nothing from `node:*` so probes can depend on it
 * without tripping the networking-import guardrail. It lives beside the
 * function that produces it, in `proxy-connect.ts`.
 */
export interface TlsCaptureTiming {
  connectMs: number | null;
  tlsMs: number | null;
}

/**
 * A captured chain, or the phase it died in. The phases stay separate for the
 * same reason `EndpointAttempt`'s do (CLAUDE.md): a name that will not
 * resolve, a port that is closed, a proxy that answered the CONNECT itself and
 * a handshake that is being interfered with are four different tickets.
 *
 * `tunnel` is the one phase `EndpointAttempt` has no equivalent for, and it is
 * here for the reason ADR-0024 gives: a capture may run over a proxy tunnel,
 * and folding "the proxy refused" into `connect` hands the probe an `HTTP_407`
 * wearing a transport failure's phase - the commonest enterprise case, made
 * unrecognisable. There is no `http`: this seam never issues a request.
 *
 * Named rather than inline because the set is a vocabulary two other files
 * exhaust: the tls probe's per-phase verdict tables, and the evidence-kinds
 * guardrail, whose `Record<Union, true>` shape turns adding a phase here into
 * a typecheck failure there rather than a widened `text` vocabulary.
 */
export type TlsCapturePhase = 'dns' | 'connect' | 'tunnel' | 'tls';

export type TlsChainOutcome =
  | {
      ok: true;
      /** Leaf first, as presented, one DER-encoded certificate per element. */
      chainDer: readonly Uint8Array[];
      negotiatedProtocol: string | null;
      negotiatedCipher: string | null;
      /** The SNI actually sent; the empty string when the target was a literal address. */
      requestedSni: string;
      timing: TlsCaptureTiming;
    }
  | {
      ok: false;
      /** Chronological, so a reader can see how far the capture got. */
      phase: TlsCapturePhase;
      code: string | null;
      abortedBy: 'phase-timeout' | 'run-signal' | null;
    };

export interface TlsCaptureTarget {
  host: string;
  port: number;
  /** Present only when capturing through a proxy CONNECT tunnel; absent means direct. */
  viaProxy?: { host: string; port: number };
}

export interface TlsCaptureOptions {
  signal: AbortSignal;
  guard: NetworkGuard;
  connectTimeoutMs: number;
  tlsTimeoutMs: number;
}

export interface TlsCapture {
  capture(target: TlsCaptureTarget, options: TlsCaptureOptions): Promise<TlsChainOutcome>;
}

/**
 * The trust-store seam (M4, ADR-0032/ADR-0033/ADR-0036). Two readers, one
 * shape: the platform's own store, and the store each *runtime* consults. Both
 * follow ADR-0008 - data comes out, an `Error` never does - because "there is
 * no `security` binary in this container" and "this JDK's cacerts is
 * password-protected" are ordinary answers a report has to carry, not
 * exceptional control flow.
 *
 * Everything here is types only, so the probe can import it without tripping
 * the `node:` import scans; the implementations live in `os-truststore.ts` and
 * `runtime-stores.ts`, which are the only files that touch a process or a file.
 */

/** Which store was read, as our own closed vocabulary. Reported as `text` evidence. */
export type TrustStoreKind =
  | 'macos-system-roots' // /System/Library/Keychains/SystemRootCertificates.keychain
  | 'macos-admin-anchors' // /Library/Keychains/System.keychain - MDM/admin installs land here
  | 'windows-machine-root' // the LocalMachine Root store
  | 'linux-ca-bundle'; // /etc/ssl/certs/ca-certificates.crt or /etc/pki/tls/certs/ca-bundle.crt

/** Why a store read produced nothing. Closed class: these are different tickets (CLAUDE.md). */
export type TrustStoreFailure =
  | 'unsupported-platform' // not darwin/win32/linux
  | 'reader-missing' // the absolute-path binary or the file does not exist
  | 'reader-failed' // non-zero exit, or killed by a signal
  | 'timeout' // exceeded SUBPROCESS_TIMEOUT_MS; the child was killed
  | 'output-too-large' // exceeded MAX_STORE_OUTPUT_BYTES; the child was killed
  | 'no-certificates'; // ran cleanly, parsed nothing

/** One store's read. `pems` is empty exactly when `failure` is non-null. */
export interface TrustStoreOutcome {
  kind: TrustStoreKind;
  /** Absolute path invoked or read. Emitted as `path` evidence, so redaction hashes it. */
  locator: string;
  pems: readonly string[];
  failure: TrustStoreFailure | null;
  /** Machine code only - exit:1, signal:SIGKILL, ENOENT. Never the child's stderr (ADR-0009). */
  code: string | null;
}

export interface OsTrustStoreReader {
  /** Every store this platform has. Never throws; a failure is an outcome. */
  read(options: { signal: AbortSignal; timeoutMs: number }): Promise<readonly TrustStoreOutcome[]>;
}

/**
 * One row of the pinned command table (ADR-0033). Lives here rather than in
 * `os-truststore.ts` so the probe and the guardrail can name the type without
 * importing the module that spawns processes.
 */
export interface TrustStoreCommand {
  platform: NodeJS.Platform;
  kind: TrustStoreKind;
  /** Absolute path. Never resolved through PATH (ADR-0033). */
  file: string;
  /** String literals only: no interpolation, no concatenation. Pinned by the guardrail. */
  argv: readonly string[];
  /** How stdout becomes PEMs. */
  format: 'pem-stream' | 'base64-der-lines';
}

/** Where a runtime looks for roots. One value per store, not per runtime. */
export type RuntimeStoreKind =
  | 'node-bundled' // tls.rootCertificates, via net/root-bundle.ts
  | 'node-extra-ca' // NODE_EXTRA_CA_CERTS - Node *adds* these to the bundle
  | 'go-ssl-cert-file' // SSL_CERT_FILE   - replaces the set
  | 'go-ssl-cert-dir' // SSL_CERT_DIR    - replaces the set
  | 'python-certifi' // site-packages/certifi/cacert.pem, found by path
  | 'python-ssl-cert-file' // SSL_CERT_FILE
  | 'python-requests-ca-bundle' // REQUESTS_CA_BUNDLE - replaces certifi for `requests`
  | 'java-cacerts' // JAVA_HOME lib/security/cacerts and the well-known JDK paths
  | 'platform-verifier'; // this runtime asks the OS here (D9). `pems` is empty.

export type RuntimeStoreFailure =
  | 'not-configured' // the env var this kind names is unset - not an error
  | 'not-found' // the well-known paths were searched and nothing was there
  | 'unreadable' // exists, open/read failed. `code` carries the errno
  | 'output-too-large' // exceeded MAX_RUNTIME_STORE_BYTES
  | 'unsupported-format' // a keystore whose magic is neither JKS nor PKCS#12 (D8)
  | 'unsupported-encoding' // indefinite-length BER inside a PKCS#12 keystore (D8)
  | 'truncated' // a length field runs past the end of the file
  | 'encrypted' // cert bags are password-protected; portcall supplies none (D8)
  | 'no-certificates'; // parsed cleanly, nothing in it

export interface RuntimeStoreOutcome {
  runtime: Runtime; // from profiles/schema.ts
  kind: RuntimeStoreKind;
  /** Path or env-var name. `path` evidence. Null for `node-bundled` and `platform-verifier`. */
  locator: string | null;
  /** How this store combines with its siblings for the same runtime. See `trustSets`. */
  combines: 'adds-to' | 'replaces' | 'standalone';
  pems: readonly string[];
  /** Keystores only: which container was actually found. Recorded as evidence. */
  format: 'jks' | 'pkcs12' | null;
  /** True when some bags were read and others were encrypted. The finding says so. */
  partial: boolean;
  failure: RuntimeStoreFailure | null;
  /** Machine code only - ENOENT, EACCES. Never a message. */
  code: string | null;
}

export interface RuntimeStoreReader {
  read(
    runtimes: readonly Runtime[],
    options: { env: NodeJS.ProcessEnv; platform: NodeJS.Platform; maxBytes: number },
  ): Promise<readonly RuntimeStoreOutcome[]>;
}
