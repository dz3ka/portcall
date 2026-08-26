/**
 * Proxy discovery for the `tls` probe: the environment variables, and nothing
 * else (ADR-0023).
 *
 * The proxy probe has three discovery legs — a profile-declared PAC URL, these
 * variables, and WPAD — and this one deliberately has one. Extracting a proxy
 * from a PAC result means running the PAC sandbox again per endpoint, and the
 * question here is narrower than the proxy probe's: is there a second path to
 * this endpoint worth capturing a chain over. The env vars answer that for
 * every runtime portcall predicts for, and the answer costs no evaluation.
 *
 * The precedence and the parsing are the proxy probe's own for this leg
 * (`envProxyFor`/`parseProxyUrl` in `src/probes/proxy/index.ts`), with one
 * simplification: there is no port to branch on, because every capture this
 * probe makes is a TLS capture, so `HTTPS_PROXY` always leads.
 *
 * `env` is a parameter rather than a read of `process.env` for the reason the
 * whole directory keeps `node:*` out (`test/guardrails/x509-parse-only.test.ts`):
 * the environment is input, and input arrives at the edge.
 */
export function discoverEnvProxy(env: NodeJS.ProcessEnv): { host: string; port: number } | null {
  const raw = readEnvVar(env, 'HTTPS_PROXY') ?? readEnvVar(env, 'HTTP_PROXY');
  return raw === null ? null : parseProxyUrl(raw);
}

function readEnvVar(env: NodeJS.ProcessEnv, name: string): string | null {
  const trimmed = (env[name] ?? env[name.toLowerCase()])?.trim();
  return trimmed !== undefined && trimmed !== '' ? trimmed : null;
}

/**
 * Only `.hostname` and `.port` are ever read off the parsed URL — never
 * `.username`/`.password`. `HTTP_PROXY`/`HTTPS_PROXY` routinely carry embedded
 * Basic auth (`http://user:pass@proxy:8080`, curl's own convention), and a
 * credential in the environment may not reach a finding, a socket or a header
 * (SPEC.md §4).
 */
function parseProxyUrl(raw: string): { host: string; port: number } | null {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const parsed = new URL(withScheme);
    if (parsed.hostname === '') return null;
    const port = parsed.port !== '' ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80;
    return { host: parsed.hostname, port };
  } catch {
    return null;
  }
}
