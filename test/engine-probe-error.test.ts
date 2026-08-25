import { describe, expect, it } from 'vitest';
import type { Evidence, EvidenceKind, Finding } from '../src/model/finding.ts';
import { NetworkPolicyError } from '../src/net/guard.ts';
import { probeErrorFinding } from '../src/engine/probe-error.ts';

/**
 * ADR-0005: `text` evidence and `remediation` cross the redaction boundary
 * unhashed (`src/redact/index.ts` hashes only the identifier kinds, and skips
 * `remediation` entirely). A thrown error's `.message` is the least bounded
 * string in the whole tool - `NetworkPolicyError` embeds `host:port`, and
 * Node's own errors embed hostnames, addresses and absolute paths - so the
 * engine's catch must never read one.
 *
 * These tests are the pin for that: they assert what the finding *does* carry
 * (a class from a closed union, a machine code, and for a policy denial the
 * host under `kind: 'hostname'` so redaction hashes it) and, more importantly,
 * that no fragment of the message survives anywhere it would be emitted
 * verbatim. No mock, no socket: `probeErrorFinding` is pure.
 */

/** The kinds `redact()` passes through verbatim - see `SENSITIVE_KINDS`. */
const UNHASHED_KINDS: ReadonlySet<EvidenceKind> = new Set<EvidenceKind>(['text', 'number', 'public']);

/** Everything the finding emits, hashed or not. */
function allValues(finding: Finding): string[] {
  const values = finding.evidence.map((evidence) => evidence.value);
  return finding.remediation === undefined ? values : [...values, finding.remediation];
}

/** Only what reaches the report in cleartext: unhashed evidence plus the remediation. */
function unhashedValues(finding: Finding): string[] {
  const values = finding.evidence
    .filter((evidence) => UNHASHED_KINDS.has(evidence.kind))
    .map((evidence) => evidence.value);
  return finding.remediation === undefined ? values : [...values, finding.remediation];
}

function evidenceFor(finding: Finding, label: string): Evidence {
  const match = finding.evidence.find((evidence) => evidence.label === label);
  if (match === undefined) {
    throw new Error(`no '${label}' evidence in [${finding.evidence.map((e) => e.label).join(', ')}]`);
  }
  return match;
}

function classOf(finding: Finding): string {
  return evidenceFor(finding, 'error class').value;
}

function codeOf(finding: Finding): string {
  return evidenceFor(finding, 'code').value;
}

describe('probeErrorFinding', () => {
  it('carries no part of a NetworkPolicyError message into evidence', () => {
    const finding = probeErrorFinding('egress', new NetworkPolicyError('build-07.corp.local', 8443));

    // The message prose appears nowhere at all, hashed or not.
    for (const value of allValues(finding)) {
      expect(value).not.toContain('refusing to connect');
      expect(value).not.toContain('not named in the active profile');
      expect(value).not.toContain('8443');
    }
    // The host appears only under `hostname`, which redaction hashes - never in
    // a value that would be emitted in cleartext.
    for (const value of unhashedValues(finding)) {
      expect(value).not.toContain('build-07');
      expect(value).not.toContain('corp.local');
    }

    expect(finding.evidence).toContainEqual({ label: 'error class', value: 'network-policy', kind: 'text' });
    expect(evidenceFor(finding, 'host')).toEqual({
      label: 'host',
      value: 'build-07.corp.local',
      kind: 'hostname',
    });
    // Appended last, so the class and the code read first in every report.
    expect(finding.evidence.map((evidence) => evidence.label)).toEqual(['error class', 'code', 'host']);
  });

  it('carries no part of a resolver error message into evidence', () => {
    const error = Object.assign(new Error('getaddrinfo ENOTFOUND internal.corp.example'), {
      code: 'ENOTFOUND',
    });

    const finding = probeErrorFinding('dns', error);

    expect(classOf(finding)).toBe('unclassified');
    expect(codeOf(finding)).toBe('ENOTFOUND');
    for (const value of allValues(finding)) {
      expect(value).not.toContain('internal.corp.example');
      expect(value).not.toContain('getaddrinfo');
    }
    // No host evidence: only a policy denial has a host we put there ourselves.
    expect(finding.evidence.map((evidence) => evidence.label)).toEqual(['error class', 'code']);
  });

  it('classifies an aborted probe and points at --timeout', () => {
    const error = Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });

    const finding = probeErrorFinding('egress', error);

    expect(classOf(finding)).toBe('aborted');
    expect(finding.remediation).toContain('--timeout');
    expect(finding.remediation).toContain('egress');
    for (const value of allValues(finding)) {
      expect(value).not.toContain('The operation was aborted');
      expect(value).not.toContain('AbortError');
    }
  });

  it('classifies a TimeoutError as aborted too', () => {
    const error = Object.assign(new Error('The operation timed out'), { name: 'TimeoutError' });

    expect(classOf(probeErrorFinding('dns', error))).toBe('aborted');
  });

  it('never stringifies a thrown non-Error', () => {
    // The `String(error)` path a future reader will be tempted to restore.
    const finding = probeErrorFinding('dns', 'boom');

    expect(classOf(finding)).toBe('unclassified');
    expect(codeOf(finding)).toBe('unavailable');
    for (const value of allValues(finding)) expect(value).not.toContain('boom');
  });

  it('reports no code when .code is prose rather than an errno', () => {
    const error = Object.assign(new Error('handshake failed'), {
      code: 'unable to verify the first certificate for corp-proxy.internal',
    });

    const finding = probeErrorFinding('egress', error);

    expect(codeOf(finding)).toBe('unavailable');
    for (const value of allValues(finding)) expect(value).not.toContain('corp-proxy.internal');
  });

  it('keeps the finding identity the engine has always emitted', () => {
    const finding = probeErrorFinding('egress', new Error('anything'));

    expect(finding.id).toBe('egress.probe-error');
    expect(finding.probe).toBe('egress');
    expect(finding.title).toBe('The egress probe could not complete');
  });

  it.each([
    ['network policy', new NetworkPolicyError('build-07.corp.local', 8443)],
    ['abort', Object.assign(new Error('aborted'), { name: 'AbortError' })],
    ['plain error', new Error('anything')],
    ['non-Error', 'boom'],
  ])('is remediable and unknown-severity for a %s throw', (_label, error: unknown) => {
    const finding = probeErrorFinding('dns', error);

    // `unknown` is never capped and exits non-zero (ADR-0006), so a probe that
    // died cannot be mistaken for a probe that passed.
    expect(finding.severity).toBe('unknown');
    expect(finding.remediation).toBeDefined();
    expect(finding.remediation?.trim()).not.toBe('');
    expect(finding.remediation).toContain('dns');
  });
});
