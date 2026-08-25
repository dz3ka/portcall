import type { Profile } from '../profiles/schema.ts';

/**
 * Network policy (SPEC.md 4, non-negotiable 3): no network calls except to
 * hosts named in the active profile.
 *
 * Like redaction, this boundary is built before the first probe exists so that
 * no probe can be written that quietly bypasses it. Every socket a probe opens
 * goes through `assertAllowed` first; a guardrail test asserts that no module
 * outside `src/net/` imports a networking API directly.
 *
 * Hosts discovered at runtime (a proxy named in `HTTPS_PROXY`, a PAC server
 * found via WPAD) are not in the profile but must still be reachable for the
 * proxy probe to say anything useful. They are admitted explicitly through
 * `permit()`, with a reason, so the report can state every host that was
 * contacted and why.
 */

export class NetworkPolicyError extends Error {
  readonly host: string;
  readonly port: number;

  constructor(host: string, port: number) {
    super(
      `refusing to connect to ${host}:${port}: not named in the active profile. ` +
        `Portcall only contacts hosts the profile declares.`,
    );
    this.name = 'NetworkPolicyError';
    this.host = host;
    this.port = port;
  }
}

export interface PermittedHost {
  host: string;
  ports: Set<number>;
  reason: string;
}

export class NetworkGuard {
  readonly #allowed = new Map<string, PermittedHost>();

  constructor(profile: Profile) {
    for (const endpoint of profile.endpoints) {
      this.permit(endpoint.host, endpoint.port, `profile endpoint: ${endpoint.purpose}`);
    }
  }

  permit(host: string, port: number, reason: string): void {
    const key = host.trim().toLowerCase();
    const existing = this.#allowed.get(key);
    if (existing === undefined) {
      this.#allowed.set(key, { host: key, ports: new Set([port]), reason });
      return;
    }
    existing.ports.add(port);
  }

  isAllowed(host: string, port: number): boolean {
    const entry = this.#allowed.get(host.trim().toLowerCase());
    return entry !== undefined && entry.ports.has(port);
  }

  assertAllowed(host: string, port: number): void {
    if (!this.isAllowed(host, port)) throw new NetworkPolicyError(host, port);
  }

  /** Every host this run is permitted to contact, for disclosure in the report. */
  permitted(): PermittedHost[] {
    return [...this.#allowed.values()].sort((a, b) => a.host.localeCompare(b.host));
  }
}
