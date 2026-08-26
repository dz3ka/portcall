import type { AuthScheme } from '../../net/types.ts';

/**
 * `WWW-Authenticate`/`Proxy-Authenticate` scheme classification (M2).
 *
 * Pure, and structurally incapable of extracting or echoing credentials: the
 * return type is a five-member closed enum with no slot for the header's
 * `realm`/other parameters, so nothing but the scheme name can ever leave
 * this function (SPEC.md §4 — the probe reports the auth scheme demanded, it
 * never authenticates).
 */

/** Earliest-listed known scheme wins — the server's stated preference. */
const SCHEME_PATTERN = /\b(Negotiate|NTLM|Basic)\b/gi;

export function classifyAuthScheme(headerValue: string | null): AuthScheme {
  if (headerValue === null) return 'none';
  const trimmed = headerValue.trim();
  if (trimmed === '') return 'none';

  let earliest: { scheme: AuthScheme; index: number } | null = null;
  for (const match of trimmed.matchAll(SCHEME_PATTERN)) {
    const token = match[0].toLowerCase();
    const scheme: AuthScheme = token === 'negotiate' ? 'Negotiate' : token === 'ntlm' ? 'NTLM' : 'Basic';
    if (earliest === null || match.index < earliest.index) earliest = { scheme, index: match.index };
  }

  return earliest?.scheme ?? 'unknown';
}
