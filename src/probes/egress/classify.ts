import type { Severity } from '../../model/finding.ts';
import type { EndpointAttempt } from '../../net/types.ts';

/**
 * Egress failure classes (M1).
 *
 * Pure: this module imports types only, never a socket API, so the whole
 * error-to-class table is testable from fixtures without a network.
 *
 * The classes exist because they route to *different teams*. `refused` is a
 * host that answered "no" (a firewall rule, a service that is down);
 * `unreachable` is a routing or NAT problem the network team owns; `reset` is a
 * connection killed mid-flight, which in an enterprise almost always means an
 * inline security appliance. Collapsing any of them into "connection failed"
 * sends the operator to the wrong desk, so they stay separate.
 */
export type EgressClass =
  | 'ok'
  | 'dns'
  | 'refused'
  | 'unreachable'
  | 'timeout'
  | 'reset'
  | 'tls'
  | 'http'
  | 'unclassified';

/** Resolver failures. `REFUSED`/`SERVFAIL`/`NXDOMAIN` are DNS rcodes, not socket errnos. */
const DNS_CODES: ReadonlySet<string> = new Set([
  'ENOTFOUND',
  'EAI_AGAIN',
  'EAI_NODATA',
  'ENODATA',
  'NXDOMAIN',
  'SERVFAIL',
  'REFUSED',
  'ETIMEOUT',
]);

/** No route to the host, or no usable local address to route from. */
const UNREACHABLE_CODES: ReadonlySet<string> = new Set([
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
  'EADDRNOTAVAIL',
]);

const TIMEOUT_CODES: ReadonlySet<string> = new Set(['ETIMEDOUT', 'ERR_SOCKET_CONNECTION_TIMEOUT']);

/** A peer that hung up on us. On `connect`/`http` this is a reset; on `tls` it is interception. */
const RESET_CODES: ReadonlySet<string> = new Set(['ECONNRESET', 'EPIPE']);

const TLS_CODES: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'EPIPE',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ERR_TLS_CERT_ALTNAME_INVALID',
]);

const TLS_PREFIXES: readonly string[] = ['ERR_TLS_', 'ERR_SSL_', 'CERT_'];

/** Node's HTTP parser (`HPE_*`) and its own HTTP client errors. */
const HTTP_PREFIXES: readonly string[] = ['HPE_', 'ERR_HTTP_'];

function hasPrefix(code: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => code.startsWith(prefix));
}

/**
 * Map one attempt to the class that names who has to fix it.
 *
 * Two ordering decisions are load-bearing:
 *
 * 1. The DNS row is checked before the timeout row, so a resolver timeout on
 *    the `dns` phase stays `dns` even when the phase watchdog also fired. The
 *    ticket goes to the DNS team either way, and `timeout` would lose that.
 * 2. Otherwise `abortedBy: 'phase-timeout'` outranks the error code, because a
 *    socket torn down by our own watchdog reports whatever errno the teardown
 *    happened to produce (commonly `ECONNRESET`), and that errno is an artifact
 *    of us, not evidence about the network.
 *
 * `abortedBy: 'run-signal'` is *not* a network observation at all: the whole
 * run was cancelled, so we learned nothing about this endpoint. WP4 checks for
 * it before calling here and emits an `*.aborted` finding. Handed one anyway,
 * we return `unclassified` (severity `unknown`, exit 1) rather than inventing
 * `timeout` — the honest answer is "we could not tell".
 *
 * Status-based classification is deliberately *not* folded in here: an attempt
 * can be `ok: true` and still have been answered by a proxy. That is
 * `classifyStatus`'s call, made separately by the caller.
 */
export function classifyAttempt(attempt: EndpointAttempt): EgressClass {
  if (attempt.ok) return 'ok';

  const { phase, code, abortedBy } = attempt;

  if (phase === 'dns' && code !== null && DNS_CODES.has(code)) return 'dns';
  if (code === 'ECONNREFUSED') return 'refused';
  if (code !== null && UNREACHABLE_CODES.has(code)) return 'unreachable';
  if (abortedBy === 'phase-timeout' || (code !== null && TIMEOUT_CODES.has(code))) return 'timeout';
  if (code === null) return 'unclassified';
  if ((phase === 'connect' || phase === 'http') && RESET_CODES.has(code)) return 'reset';
  if (phase === 'tls' && (TLS_CODES.has(code) || hasPrefix(code, TLS_PREFIXES))) return 'tls';
  if (phase === 'http' && hasPrefix(code, HTTP_PREFIXES)) return 'http';

  /*
   * The OS error space cannot be exhaustively mapped, and a wrong guess costs
   * more than an admission: it sends an operator to the wrong team with false
   * confidence. `unclassified` becomes an `unknown` finding and exit code 1
   * (ADR-0006), which says "this ran and could not decide" without claiming a
   * pass.
   */
  return 'unclassified';
}

/**
 * Statuses that mean an intermediary answered instead of the origin: proxy auth
 * required, captive portal, and the gateway-level 5xx family a filtering
 * appliance emits when it refuses to forward.
 */
const INTERMEDIARY_STATUSES: ReadonlySet<number> = new Set([407, 511, 502, 503, 504]);

/**
 * A 404 on `GET /` is a pass. The question this probe asks is "can I reach the
 * origin", not "does it serve a page at the root", so only statuses that
 * indicate an intermediary spoke for it are failures.
 */
export function classifyStatus(status: number): 'ok' | 'http' {
  return INTERMEDIARY_STATUSES.has(status) ? 'http' : 'ok';
}

/**
 * Cap a severity by whether the endpoint is required by the profile.
 *
 * An optional endpoint (say `registry.npmjs.org` for a tool that ships its own
 * deps) being blocked is worth a `degraded`, never a `blocker` — a blocker
 * exits 2 and gates the customer's CI over something the tool works without.
 *
 * `unknown` is never capped. It is not a severity on the same axis: it means
 * the check could not decide, and how important the endpoint is has no bearing
 * on that. Capping it would also silently turn "we could not tell" into a
 * softer-sounding verdict we did not earn.
 */
export function cap(severity: Severity, required: boolean): Severity {
  if (required) return severity;

  switch (severity) {
    case 'blocker':
      return 'degraded';
    case 'degraded':
    case 'ok':
    case 'unknown':
      return severity;
  }
}
